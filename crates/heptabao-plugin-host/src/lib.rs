#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! A fail-closed plugin process boundary and dynamic-secret lease coordinator.
//!
//! The host never executes a plugin directly. A separately installed sandbox
//! provider must attest the manifest and launch the descriptor-bound executable.
//! Requests and responses use a bounded binary frame; post-spawn uncertainty
//! fences further calls until an explicit reconciliation proof is supplied.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use heptabao_domain::{CanonicalPath, DomainError, Id, SecretValue, Tick};
use heptabao_plugin_contracts::{PluginDescriptor, PluginKind, PluginStatus};
use ring::digest::{Context, SHA256};
use zeroize::Zeroizing;

mod durable;
pub use durable::{
    DurableDynamicSecretBroker, DurableReconciliationDecision, PendingPluginInvocation,
    PluginMutationContext,
};

const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 16 * 1024;
const MAX_LEASE_TTL: u64 = 366 * 24 * 60 * 60;
const REQUEST_MAGIC: &[u8; 4] = b"HBP1";
const RESPONSE_MAGIC: &[u8; 4] = b"HBR1";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PluginOperation {
    Read,
    Write,
    Issue,
    Renew,
    Revoke,
}

impl PluginOperation {
    const fn tag(self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Issue => 3,
            Self::Renew => 4,
            Self::Revoke => 5,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Issue => "issue",
            Self::Renew => "renew",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub timeout_ms: u64,
}

impl PluginLimits {
    pub fn validate(self) -> Result<Self, PluginHostError> {
        if self.maximum_request_bytes == 0
            || self.maximum_request_bytes > MAX_REQUEST_BYTES
            || self.maximum_response_bytes == 0
            || self.maximum_response_bytes > MAX_RESPONSE_BYTES
            || !(1..=60_000).contains(&self.timeout_ms)
        {
            return Err(PluginHostError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxBinding {
    pub provider_id: Id,
    pub command: CanonicalPath,
    pub command_sha256: [u8; 32],
    pub profile_id: Id,
}

impl SandboxBinding {
    pub fn new(
        provider_id: Id,
        command: CanonicalPath,
        command_sha256: [u8; 32],
        profile_id: Id,
    ) -> Result<Self, PluginHostError> {
        if command_sha256 == [0; 32] {
            return Err(PluginHostError::InvalidSandboxBinding);
        }
        Ok(Self {
            provider_id,
            command,
            command_sha256,
            profile_id,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginManifest {
    descriptor: PluginDescriptor,
    sandbox: SandboxBinding,
    limits: PluginLimits,
    operations: BTreeSet<PluginOperation>,
    environment_allowlist: BTreeSet<String>,
}

impl PluginManifest {
    pub fn new(
        descriptor: PluginDescriptor,
        sandbox: SandboxBinding,
        limits: PluginLimits,
        operations: BTreeSet<PluginOperation>,
        environment_allowlist: BTreeSet<String>,
    ) -> Result<Self, PluginHostError> {
        if descriptor.status() != PluginStatus::Enabled {
            return Err(PluginHostError::PluginNotEnabled);
        }
        if operations.is_empty() || !operations_are_valid_for_kind(descriptor.kind(), &operations) {
            return Err(PluginHostError::CapabilityDenied);
        }
        if environment_allowlist.len() > MAX_ENVIRONMENT_ENTRIES
            || environment_allowlist
                .iter()
                .any(|name| !valid_environment_name(name))
        {
            return Err(PluginHostError::InvalidEnvironment);
        }
        Ok(Self {
            descriptor,
            sandbox,
            limits: limits.validate()?,
            operations,
            environment_allowlist,
        })
    }

    pub fn descriptor(&self) -> &PluginDescriptor {
        &self.descriptor
    }

    pub fn sandbox(&self) -> &SandboxBinding {
        &self.sandbox
    }

    pub const fn limits(&self) -> PluginLimits {
        self.limits
    }

    pub fn operations(&self) -> &BTreeSet<PluginOperation> {
        &self.operations
    }

    pub fn environment_allowlist(&self) -> &BTreeSet<String> {
        &self.environment_allowlist
    }
}

fn operations_are_valid_for_kind(kind: PluginKind, operations: &BTreeSet<PluginOperation>) -> bool {
    match kind {
        PluginKind::Secrets | PluginKind::Database => true,
        PluginKind::Authentication => operations
            .iter()
            .all(|operation| matches!(operation, PluginOperation::Read | PluginOperation::Write)),
        PluginKind::Audit => operations
            .iter()
            .all(|operation| matches!(operation, PluginOperation::Write)),
    }
}

pub struct SecretEnvironment {
    values: BTreeMap<String, Zeroizing<String>>,
}

impl SecretEnvironment {
    pub fn new() -> Self {
        Self {
            values: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, name: &str, value: String) -> Result<(), PluginHostError> {
        if !valid_environment_name(name)
            || value.is_empty()
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.contains('\0')
            || self.values.len() >= MAX_ENVIRONMENT_ENTRIES && !self.values.contains_key(name)
        {
            return Err(PluginHostError::InvalidEnvironment);
        }
        self.values.insert(name.to_owned(), Zeroizing::new(value));
        Ok(())
    }

    fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }
}

impl Default for SecretEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEnvironment")
            .field("names", &self.values.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxFailure {
    BeforeEntry,
    OutcomeUnknownAfterEntry,
}

pub trait SandboxRunner: fmt::Debug {
    fn admit(&self, manifest: &PluginManifest) -> Result<(), SandboxFailure>;

    fn invoke(
        &self,
        manifest: &PluginManifest,
        operation: PluginOperation,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<SecretValue, SandboxFailure>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSandboxRunner;

impl SandboxRunner for CommandSandboxRunner {
    fn admit(&self, manifest: &PluginManifest) -> Result<(), SandboxFailure> {
        verify_file(
            Path::new(manifest.sandbox().command.as_str()),
            manifest.sandbox().command_sha256,
        )?;
        verify_file(
            Path::new(manifest.descriptor().command().as_str()),
            *manifest.descriptor().checksum(),
        )?;
        Ok(())
    }

    fn invoke(
        &self,
        manifest: &PluginManifest,
        operation: PluginOperation,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<SecretValue, SandboxFailure> {
        self.admit(manifest)?;
        if request.len() > manifest.limits().maximum_request_bytes {
            return Err(SandboxFailure::BeforeEntry);
        }
        if environment
            .iter()
            .any(|(name, _)| !manifest.environment_allowlist().contains(name))
        {
            return Err(SandboxFailure::BeforeEntry);
        }
        let frame = encode_request(
            manifest.descriptor().protocol_version(),
            operation,
            request.expose(),
        )
        .map_err(|_| SandboxFailure::BeforeEntry)?;
        let mut command = Command::new(manifest.sandbox().command.as_str());
        command
            .arg("--heptabao-profile")
            .arg(manifest.sandbox().profile_id.as_str())
            .arg("--heptabao-plugin")
            .arg(manifest.descriptor().command().as_str())
            .arg("--heptabao-protocol")
            .arg(manifest.descriptor().protocol_version().to_string())
            .arg("--heptabao-operation")
            .arg(operation.as_str())
            .env_clear()
            .env(
                "HEPTABAO_SANDBOX_PROVIDER",
                manifest.sandbox().provider_id.as_str(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (name, value) in environment.iter() {
            command.env(name, value);
        }
        let mut child = command.spawn().map_err(|_| SandboxFailure::BeforeEntry)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        if stdin.write_all(&frame).is_err() || stdin.flush().is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxFailure::OutcomeUnknownAfterEntry);
        }
        drop(stdin);
        let stdout = child
            .stdout
            .take()
            .ok_or(SandboxFailure::OutcomeUnknownAfterEntry)?;
        let maximum = manifest
            .limits()
            .maximum_response_bytes
            .checked_add(9)
            .ok_or(SandboxFailure::BeforeEntry)?;
        let reader = thread::spawn(move || read_bounded(stdout, maximum));
        let deadline = Instant::now() + Duration::from_millis(manifest.limits().timeout_ms);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(SandboxFailure::OutcomeUnknownAfterEntry);
                }
            }
        };
        let output = reader
            .join()
            .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)?
            .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)?;
        if !status.success() {
            return Err(SandboxFailure::OutcomeUnknownAfterEntry);
        }
        decode_response(&output, manifest.limits().maximum_response_bytes)
            .map_err(|_| SandboxFailure::OutcomeUnknownAfterEntry)
    }
}

fn verify_file(path: &Path, expected: [u8; 32]) -> Result<(), SandboxFailure> {
    if !path.is_absolute() || !path_components_are_real(path) {
        return Err(SandboxFailure::BeforeEntry);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| SandboxFailure::BeforeEntry)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(SandboxFailure::BeforeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 || mode & 0o100 == 0 {
            return Err(SandboxFailure::BeforeEntry);
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0o400000 | 0o2000000);
    }
    let mut file = options
        .open(path)
        .map_err(|_| SandboxFailure::BeforeEntry)?;
    let opened = file.metadata().map_err(|_| SandboxFailure::BeforeEntry)?;
    if !opened.is_file() || opened.len() != metadata.len() {
        return Err(SandboxFailure::BeforeEntry);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(SandboxFailure::BeforeEntry);
        }
    }
    let mut digest = Context::new(&SHA256);
    let mut buffer = [0_u8; 16 * 1024];
    let mut observed = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| SandboxFailure::BeforeEntry)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or(SandboxFailure::BeforeEntry)?;
        if observed > MAX_EXECUTABLE_BYTES {
            return Err(SandboxFailure::BeforeEntry);
        }
        digest.update(&buffer[..count]);
    }
    if digest.finish().as_ref() != expected {
        return Err(SandboxFailure::BeforeEntry);
    }
    Ok(())
}

fn path_components_are_real(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                if current.as_os_str().is_empty() || current == Path::new("/") {
                    continue;
                }
                let Ok(metadata) = fs::symlink_metadata(&current) else {
                    return false;
                };
                if metadata.file_type().is_symlink() {
                    return false;
                }
            }
            Component::CurDir | Component::ParentDir => return false,
        }
    }
    true
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut output)?;
    if output.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds bound",
        ));
    }
    Ok(output)
}

fn encode_request(
    protocol_version: u16,
    operation: PluginOperation,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PluginHostError> {
    let length = u32::try_from(payload.len()).map_err(|_| PluginHostError::RequestTooLarge)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(11 + payload.len()));
    frame.extend_from_slice(REQUEST_MAGIC);
    frame.extend_from_slice(&protocol_version.to_be_bytes());
    frame.push(operation.tag());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn decode_response(bytes: &[u8], maximum: usize) -> Result<SecretValue, PluginHostError> {
    if bytes.len() < 8 || &bytes[..4] != RESPONSE_MAGIC {
        return Err(PluginHostError::MalformedResponse);
    }
    let length = u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| PluginHostError::MalformedResponse)?,
    ) as usize;
    if length == 0 || length > maximum || bytes.len() != 8 + length {
        return Err(if length > maximum {
            PluginHostError::ResponseTooLarge
        } else {
            PluginHostError::MalformedResponse
        });
    }
    SecretValue::new(bytes[8..].to_vec()).map_err(PluginHostError::Domain)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginHostState {
    Active,
    ReconciliationRequired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationProof {
    ProvenNoEffect,
    Completed { response_digest: [u8; 32] },
}

#[derive(Debug)]
pub struct PluginHost<R: SandboxRunner> {
    manifest: PluginManifest,
    runner: R,
    state: PluginHostState,
}

impl<R: SandboxRunner> PluginHost<R> {
    pub fn admit(manifest: PluginManifest, runner: R) -> Result<Self, PluginHostError> {
        runner
            .admit(&manifest)
            .map_err(|_| PluginHostError::SandboxUnavailable)?;
        Ok(Self {
            manifest,
            runner,
            state: PluginHostState::Active,
        })
    }

    pub const fn state(&self) -> PluginHostState {
        self.state
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn invoke(
        &mut self,
        operation: PluginOperation,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<SecretValue, PluginHostError> {
        match self.state {
            PluginHostState::ReconciliationRequired => {
                return Err(PluginHostError::ReconciliationRequired);
            }
            PluginHostState::Revoked => return Err(PluginHostError::PluginRevoked),
            PluginHostState::Active => {}
        }
        if !self.manifest.operations().contains(&operation) {
            return Err(PluginHostError::CapabilityDenied);
        }
        if request.len() > self.manifest.limits().maximum_request_bytes {
            return Err(PluginHostError::RequestTooLarge);
        }
        if environment
            .iter()
            .any(|(name, _)| !self.manifest.environment_allowlist().contains(name))
        {
            return Err(PluginHostError::EnvironmentDenied);
        }
        match self
            .runner
            .invoke(&self.manifest, operation, request, environment)
        {
            Ok(response) if response.len() <= self.manifest.limits().maximum_response_bytes => {
                Ok(response)
            }
            Ok(_) => {
                self.state = PluginHostState::ReconciliationRequired;
                Err(PluginHostError::ResponseTooLarge)
            }
            Err(SandboxFailure::BeforeEntry) => Err(PluginHostError::ProcessBeforeEntry),
            Err(SandboxFailure::OutcomeUnknownAfterEntry) => {
                self.state = PluginHostState::ReconciliationRequired;
                Err(PluginHostError::ProcessOutcomeUnknown)
            }
        }
    }

    pub fn reconcile(&mut self, proof: ReconciliationProof) -> Result<(), PluginHostError> {
        if self.state != PluginHostState::ReconciliationRequired {
            return Err(PluginHostError::InvalidReconciliation);
        }
        if matches!(proof, ReconciliationProof::Completed { response_digest } if response_digest == [0; 32])
        {
            return Err(PluginHostError::InvalidReconciliation);
        }
        self.runner
            .admit(&self.manifest)
            .map_err(|_| PluginHostError::SandboxUnavailable)?;
        self.state = PluginHostState::Active;
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.state = PluginHostState::Revoked;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DynamicLeaseState {
    Active,
    Revoked,
    Expired,
    ReconciliationRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicLeaseSpec {
    pub lease_id: Id,
    pub owner_entity: Id,
    pub scope: CanonicalPath,
    pub issued_at: Tick,
    pub ttl: u64,
    pub renewable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicLeaseView {
    pub lease_id: Id,
    pub owner_entity: Id,
    pub scope: CanonicalPath,
    pub state: DynamicLeaseState,
    pub issued_at: Tick,
    pub expires_at: Tick,
    pub renewable: bool,
    pub generation: u64,
    pub secret_digest: [u8; 32],
}

#[derive(Clone, Debug)]
struct DynamicLeaseRecord {
    view: DynamicLeaseView,
}

#[derive(Debug)]
pub struct DynamicSecretIssue {
    pub lease: DynamicLeaseView,
    pub secret: SecretValue,
}

#[derive(Debug)]
pub struct DynamicSecretBroker<R: SandboxRunner> {
    host: PluginHost<R>,
    leases: BTreeMap<Id, DynamicLeaseRecord>,
}

impl<R: SandboxRunner> DynamicSecretBroker<R> {
    pub fn new(host: PluginHost<R>) -> Result<Self, PluginHostError> {
        if !host
            .manifest()
            .operations()
            .contains(&PluginOperation::Issue)
            || !host
                .manifest()
                .operations()
                .contains(&PluginOperation::Revoke)
        {
            return Err(PluginHostError::CapabilityDenied);
        }
        Ok(Self {
            host,
            leases: BTreeMap::new(),
        })
    }

    pub fn host_state(&self) -> PluginHostState {
        self.host.state()
    }

    pub fn issue(
        &mut self,
        spec: DynamicLeaseSpec,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicSecretIssue, PluginHostError> {
        if spec.ttl == 0 || spec.ttl > MAX_LEASE_TTL {
            return Err(PluginHostError::InvalidLeaseTtl);
        }
        if self.leases.contains_key(&spec.lease_id) {
            return Err(PluginHostError::DuplicateLease);
        }
        let expires_at = spec
            .issued_at
            .checked_add(spec.ttl)
            .map_err(PluginHostError::Domain)?;
        let bound = bind_dynamic_request("issue", &spec.lease_id, 1, request)?;
        let secret = self
            .host
            .invoke(PluginOperation::Issue, &bound, environment)?;
        let view = DynamicLeaseView {
            lease_id: spec.lease_id.clone(),
            owner_entity: spec.owner_entity,
            scope: spec.scope,
            state: DynamicLeaseState::Active,
            issued_at: spec.issued_at,
            expires_at,
            renewable: spec.renewable,
            generation: 1,
            secret_digest: sha256(secret.expose()),
        };
        self.leases
            .insert(spec.lease_id, DynamicLeaseRecord { view: view.clone() });
        Ok(DynamicSecretIssue {
            lease: view,
            secret,
        })
    }

    pub fn view(&mut self, lease_id: &Id, now: Tick) -> Result<DynamicLeaseView, PluginHostError> {
        let record = self
            .leases
            .get_mut(lease_id)
            .ok_or(PluginHostError::MissingLease)?;
        if record.view.state == DynamicLeaseState::Active && now >= record.view.expires_at {
            record.view.state = DynamicLeaseState::Expired;
            record.view.generation = record
                .view
                .generation
                .checked_add(1)
                .ok_or(PluginHostError::GenerationOverflow)?;
        }
        Ok(record.view.clone())
    }

    pub fn renew(
        &mut self,
        lease_id: &Id,
        now: Tick,
        ttl: u64,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicLeaseView, PluginHostError> {
        if ttl == 0 || ttl > MAX_LEASE_TTL {
            return Err(PluginHostError::InvalidLeaseTtl);
        }
        let current = self.view(lease_id, now)?;
        if current.state != DynamicLeaseState::Active || !current.renewable {
            return Err(PluginHostError::LeaseNotRenewable);
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(PluginHostError::GenerationOverflow)?;
        let bound = bind_dynamic_request("renew", lease_id, generation, request)?;
        match self
            .host
            .invoke(PluginOperation::Renew, &bound, environment)
        {
            Ok(response) => {
                let expires_at = now.checked_add(ttl).map_err(PluginHostError::Domain)?;
                let record = self
                    .leases
                    .get_mut(lease_id)
                    .ok_or(PluginHostError::MissingLease)?;
                record.view.expires_at = expires_at;
                record.view.generation = generation;
                record.view.secret_digest = sha256(response.expose());
                Ok(record.view.clone())
            }
            Err(error) if self.host.state() == PluginHostState::ReconciliationRequired => {
                if let Some(record) = self.leases.get_mut(lease_id) {
                    record.view.state = DynamicLeaseState::ReconciliationRequired;
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn revoke(
        &mut self,
        lease_id: &Id,
        request: &SecretValue,
        environment: &SecretEnvironment,
    ) -> Result<DynamicLeaseView, PluginHostError> {
        let current = self
            .leases
            .get(lease_id)
            .map(|record| record.view.clone())
            .ok_or(PluginHostError::MissingLease)?;
        if current.state != DynamicLeaseState::Active {
            return Err(PluginHostError::LeaseNotActive);
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(PluginHostError::GenerationOverflow)?;
        let bound = bind_dynamic_request("revoke", lease_id, generation, request)?;
        match self
            .host
            .invoke(PluginOperation::Revoke, &bound, environment)
        {
            Ok(_response) => {
                let record = self
                    .leases
                    .get_mut(lease_id)
                    .ok_or(PluginHostError::MissingLease)?;
                record.view.state = DynamicLeaseState::Revoked;
                record.view.generation = generation;
                Ok(record.view.clone())
            }
            Err(error) if self.host.state() == PluginHostState::ReconciliationRequired => {
                if let Some(record) = self.leases.get_mut(lease_id) {
                    record.view.state = DynamicLeaseState::ReconciliationRequired;
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    pub fn reconcile_host(
        &mut self,
        lease_id: &Id,
        proof: ReconciliationProof,
        resolved_state: DynamicLeaseState,
    ) -> Result<DynamicLeaseView, PluginHostError> {
        if !matches!(
            resolved_state,
            DynamicLeaseState::Active | DynamicLeaseState::Revoked | DynamicLeaseState::Expired
        ) {
            return Err(PluginHostError::InvalidReconciliation);
        }
        self.host.reconcile(proof)?;
        let record = self
            .leases
            .get_mut(lease_id)
            .ok_or(PluginHostError::MissingLease)?;
        if record.view.state != DynamicLeaseState::ReconciliationRequired {
            return Err(PluginHostError::InvalidReconciliation);
        }
        record.view.state = resolved_state;
        record.view.generation = record
            .view
            .generation
            .checked_add(1)
            .ok_or(PluginHostError::GenerationOverflow)?;
        Ok(record.view.clone())
    }
}

fn bind_dynamic_request(
    action: &str,
    lease_id: &Id,
    generation: u64,
    request: &SecretValue,
) -> Result<SecretValue, PluginHostError> {
    let action_len = u16::try_from(action.len()).map_err(|_| PluginHostError::RequestTooLarge)?;
    let id_len =
        u16::try_from(lease_id.as_str().len()).map_err(|_| PluginHostError::RequestTooLarge)?;
    let request_len = u32::try_from(request.len()).map_err(|_| PluginHostError::RequestTooLarge)?;
    let mut value = Zeroizing::new(Vec::with_capacity(
        2 + action.len() + 2 + lease_id.as_str().len() + 8 + 4 + request.len(),
    ));
    value.extend_from_slice(&action_len.to_be_bytes());
    value.extend_from_slice(action.as_bytes());
    value.extend_from_slice(&id_len.to_be_bytes());
    value.extend_from_slice(lease_id.as_str().as_bytes());
    value.extend_from_slice(&generation.to_be_bytes());
    value.extend_from_slice(&request_len.to_be_bytes());
    value.extend_from_slice(request.expose());
    SecretValue::new(value.to_vec()).map_err(PluginHostError::Domain)
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn sha256(value: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&SHA256, value);
    let mut output = [0_u8; 32];
    output.copy_from_slice(digest.as_ref());
    output
}

#[derive(Debug)]
pub enum PluginHostError {
    Domain(DomainError),
    InvalidLimits,
    InvalidSandboxBinding,
    InvalidEnvironment,
    PluginNotEnabled,
    SandboxUnavailable,
    CapabilityDenied,
    RequestTooLarge,
    ResponseTooLarge,
    MalformedResponse,
    EnvironmentDenied,
    ProcessBeforeEntry,
    ProcessOutcomeUnknown,
    ReconciliationRequired,
    InvalidReconciliation,
    PluginRevoked,
    InvalidLeaseTtl,
    DuplicateLease,
    MissingLease,
    LeaseNotRenewable,
    LeaseNotActive,
    InvalidAuthorizationDigest,
    PendingPluginInvocation,
    CorruptDurablePluginState,
    Durable(heptabao_durable_service::ServiceError),
    GenerationOverflow,
}

impl fmt::Display for PluginHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Domain(_) => "plugin input violates a bounded domain contract",
            Self::InvalidLimits => "plugin resource limits are invalid or unbounded",
            Self::InvalidSandboxBinding => "sandbox binding is invalid",
            Self::InvalidEnvironment => "plugin environment is invalid or unbounded",
            Self::PluginNotEnabled => "plugin is not enabled",
            Self::SandboxUnavailable => "sandbox provider admission failed",
            Self::CapabilityDenied => "plugin operation is not declared",
            Self::RequestTooLarge => "plugin request exceeds its manifest bound",
            Self::ResponseTooLarge => "plugin response exceeds its manifest bound",
            Self::MalformedResponse => "plugin response frame is malformed",
            Self::EnvironmentDenied => "plugin environment contains an undeclared name",
            Self::ProcessBeforeEntry => "plugin process failed before effect entry",
            Self::ProcessOutcomeUnknown => "plugin process outcome is unknown after entry",
            Self::ReconciliationRequired => "plugin host is fenced pending reconciliation",
            Self::InvalidReconciliation => "plugin reconciliation proof is invalid",
            Self::PluginRevoked => "plugin is revoked",
            Self::InvalidLeaseTtl => "dynamic secret lease TTL is invalid",
            Self::DuplicateLease => "dynamic secret lease already exists",
            Self::MissingLease => "dynamic secret lease does not exist",
            Self::LeaseNotRenewable => "dynamic secret lease cannot be renewed",
            Self::LeaseNotActive => "dynamic secret lease is not active",
            Self::InvalidAuthorizationDigest => "plugin durable authorization digest is invalid",
            Self::PendingPluginInvocation => {
                "a durable plugin invocation is pending reconciliation"
            }
            Self::CorruptDurablePluginState => "durable plugin state failed closed",
            Self::Durable(_) => "durable plugin transition failed",
            Self::GenerationOverflow => "plugin or lease generation overflow",
        })
    }
}

impl Error for PluginHostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Domain(error) => Some(error),
            Self::Durable(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DomainError> for PluginHostError {
    fn from(value: DomainError) -> Self {
        Self::Domain(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heptabao_plugin_contracts::PluginRegistry;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone, Copy, Debug)]
    enum Behavior {
        Echo,
        BeforeEntry,
        OutcomeUnknown,
    }

    #[derive(Debug)]
    struct FakeRunner {
        behavior: Behavior,
    }

    impl SandboxRunner for FakeRunner {
        fn admit(&self, _manifest: &PluginManifest) -> Result<(), SandboxFailure> {
            Ok(())
        }

        fn invoke(
            &self,
            _manifest: &PluginManifest,
            _operation: PluginOperation,
            request: &SecretValue,
            _environment: &SecretEnvironment,
        ) -> Result<SecretValue, SandboxFailure> {
            match self.behavior {
                Behavior::Echo => SecretValue::new(request.expose().to_vec())
                    .map_err(|_| SandboxFailure::BeforeEntry),
                Behavior::BeforeEntry => Err(SandboxFailure::BeforeEntry),
                Behavior::OutcomeUnknown => Err(SandboxFailure::OutcomeUnknownAfterEntry),
            }
        }
    }

    fn manifest(behavior: Behavior) -> Result<PluginHost<FakeRunner>, Box<dyn Error>> {
        let plugin_id = Id::parse("database_plugin")?;
        let descriptor = PluginDescriptor::new(
            plugin_id.clone(),
            PluginKind::Database,
            CanonicalPath::parse("/opt/heptabao/plugins/database")?,
            [7; 32],
            1,
        )?;
        let mut registry = PluginRegistry::default();
        registry.register(descriptor)?;
        registry.enable(&plugin_id)?;
        let descriptor = registry.get(&plugin_id)?.clone();
        let sandbox = SandboxBinding::new(
            Id::parse("sandbox_provider")?,
            CanonicalPath::parse("/usr/bin/heptabao-sandbox")?,
            [8; 32],
            Id::parse("database_profile")?,
        )?;
        let manifest = PluginManifest::new(
            descriptor,
            sandbox,
            PluginLimits {
                maximum_request_bytes: 4096,
                maximum_response_bytes: 4096,
                timeout_ms: 1000,
            },
            BTreeSet::from([
                PluginOperation::Issue,
                PluginOperation::Renew,
                PluginOperation::Revoke,
            ]),
            BTreeSet::from(["REQUEST_ID".to_owned()]),
        )?;
        Ok(PluginHost::admit(manifest, FakeRunner { behavior })?)
    }

    #[test]
    fn undeclared_environment_and_operation_fail_before_entry() -> Result<(), Box<dyn Error>> {
        let mut host = manifest(Behavior::Echo)?;
        let request = SecretValue::new(b"synthetic-request".to_vec())?;
        let mut environment = SecretEnvironment::new();
        environment.insert("UNDECLARED", "synthetic".to_owned())?;
        assert!(matches!(
            host.invoke(PluginOperation::Issue, &request, &environment),
            Err(PluginHostError::EnvironmentDenied)
        ));
        assert!(matches!(
            host.invoke(PluginOperation::Read, &request, &SecretEnvironment::new()),
            Err(PluginHostError::CapabilityDenied)
        ));
        assert_eq!(PluginHostState::Active, host.state());
        Ok(())
    }

    #[test]
    fn outcome_unknown_fences_until_explicit_reconciliation() -> Result<(), Box<dyn Error>> {
        let mut host = manifest(Behavior::OutcomeUnknown)?;
        let request = SecretValue::new(b"synthetic-request".to_vec())?;
        assert!(matches!(
            host.invoke(PluginOperation::Issue, &request, &SecretEnvironment::new()),
            Err(PluginHostError::ProcessOutcomeUnknown)
        ));
        assert_eq!(PluginHostState::ReconciliationRequired, host.state());
        assert!(matches!(
            host.invoke(PluginOperation::Issue, &request, &SecretEnvironment::new()),
            Err(PluginHostError::ReconciliationRequired)
        ));
        host.reconcile(ReconciliationProof::ProvenNoEffect)?;
        assert_eq!(PluginHostState::Active, host.state());
        Ok(())
    }

    #[test]
    fn before_entry_failure_does_not_poison_host() -> Result<(), Box<dyn Error>> {
        let mut host = manifest(Behavior::BeforeEntry)?;
        let request = SecretValue::new(b"synthetic-request".to_vec())?;
        assert!(matches!(
            host.invoke(PluginOperation::Issue, &request, &SecretEnvironment::new()),
            Err(PluginHostError::ProcessBeforeEntry)
        ));
        assert_eq!(PluginHostState::Active, host.state());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn command_runner_uses_the_verified_wrapper_and_bounded_frame() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "heptabao-plugin-host-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let wrapper_path = root.join("sandbox-wrapper.py");
        let plugin_path = root.join("plugin-fixture");
        fs::write(
            &wrapper_path,
            concat!(
                "#!/usr/bin/python3\n",
                "import os, struct, sys\n",
                "data = sys.stdin.buffer.read()\n",
                "if len(data) < 11 or data[:4] != b'HBP1': sys.exit(2)\n",
                "length = struct.unpack('>I', data[7:11])[0]\n",
                "payload = data[11:]\n",
                "if len(payload) != length: sys.exit(3)\n",
                "if 'HOME' in os.environ: sys.exit(4)\n",
                "if os.environ.get('REQUEST_ID') != 'request-one': sys.exit(5)\n",
                "sys.stdout.buffer.write(b'HBR1' + struct.pack('>I', len(payload)) + payload)\n",
            ),
        )?;
        fs::write(&plugin_path, "#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&plugin_path, fs::Permissions::from_mode(0o700))?;

        let plugin_id = Id::parse("fixture_plugin")?;
        let mut registry = PluginRegistry::default();
        registry.register(PluginDescriptor::new(
            plugin_id.clone(),
            PluginKind::Secrets,
            CanonicalPath::parse(
                plugin_path
                    .to_str()
                    .ok_or_else(|| io::Error::other("plugin path is not UTF-8"))?,
            )?,
            sha256(&fs::read(&plugin_path)?),
            1,
        )?)?;
        registry.enable(&plugin_id)?;
        let manifest = PluginManifest::new(
            registry.get(&plugin_id)?.clone(),
            SandboxBinding::new(
                Id::parse("fixture_sandbox")?,
                CanonicalPath::parse(
                    wrapper_path
                        .to_str()
                        .ok_or_else(|| io::Error::other("wrapper path is not UTF-8"))?,
                )?,
                sha256(&fs::read(&wrapper_path)?),
                Id::parse("fixture_profile")?,
            )?,
            PluginLimits {
                maximum_request_bytes: 4096,
                maximum_response_bytes: 4096,
                timeout_ms: 2000,
            },
            BTreeSet::from([PluginOperation::Read]),
            BTreeSet::from(["REQUEST_ID".to_owned()]),
        )?;
        let mut host = PluginHost::admit(manifest, CommandSandboxRunner)?;
        let request = SecretValue::new(b"bounded-process-frame".to_vec())?;
        let mut environment = SecretEnvironment::new();
        environment.insert("REQUEST_ID", "request-one".to_owned())?;
        let response = host.invoke(PluginOperation::Read, &request, &environment)?;
        assert_eq!(request.expose(), response.expose());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn dynamic_secret_plaintext_is_not_retained_and_lifecycle_is_monotonic()
    -> Result<(), Box<dyn Error>> {
        let host = manifest(Behavior::Echo)?;
        let mut broker = DynamicSecretBroker::new(host)?;
        let request = SecretValue::new(b"synthetic-dynamic-secret".to_vec())?;
        let issue = broker.issue(
            DynamicLeaseSpec {
                lease_id: Id::parse("lease_one")?,
                owner_entity: Id::parse("owner_one")?,
                scope: CanonicalPath::parse("/database/roles/readonly")?,
                issued_at: Tick::new(10),
                ttl: 30,
                renewable: true,
            },
            &request,
            &SecretEnvironment::new(),
        )?;
        assert_eq!(sha256(issue.secret.expose()), issue.lease.secret_digest);
        let renewed = broker.renew(
            &Id::parse("lease_one")?,
            Tick::new(20),
            40,
            &request,
            &SecretEnvironment::new(),
        )?;
        assert_eq!(Tick::new(60), renewed.expires_at);
        let revoked = broker.revoke(
            &Id::parse("lease_one")?,
            &request,
            &SecretEnvironment::new(),
        )?;
        assert_eq!(DynamicLeaseState::Revoked, revoked.state);
        assert!(format!("{broker:?}").contains("DynamicSecretBroker"));
        assert!(!format!("{broker:?}").contains("synthetic-dynamic-secret"));
        Ok(())
    }
}
