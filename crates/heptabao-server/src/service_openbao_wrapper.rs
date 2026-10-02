//! Deployment-owned Wrapper launch admission, separate from HBP1 and SDK KMS.
//!
//! The server owns each configured launch and its lifecycle generation. The
//! AutoMTLS session is created from this owned launch and retained by a bounded
//! runtime. No caller-supplied endpoint/certificate or reattach path substitutes
//! for that exchange. SDK KMS and barrier envelopes remain separate consumers.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::Instant;

use heptabao_openbao_grpc::{BridgeError, HostLifecycle};
use serde::Deserialize;

use super::Service;

#[path = "service_openbao_wrapper_barrier.rs"]
pub(crate) mod barrier;

#[cfg(target_os = "linux")]
#[path = "service_openbao_wrapper_linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{WrapperCleanupState, WrapperOperation, WrapperReply};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OpenBaoWrapperTransport {
    AutoMtls,
}

/// Trusted server configuration only; no HTTP route installs these fields.
/// The private configuration file is bound by metadata/digest, never argv or
/// an inherited environment. SetConfig accepts only a bounded string map.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenBaoWrapperConfig {
    pub command: PathBuf,
    pub command_sha256: String,
    pub configuration_file: PathBuf,
    pub configuration_sha256: String,
    pub transport: OpenBaoWrapperTransport,
    /// Optional deployment-owned SoftHSM selector, held open for the entire launch.
    #[serde(default)]
    pub soft_hsm_configuration_file: Option<PathBuf>,
    #[serde(default)]
    pub soft_hsm_configuration_sha256: Option<String>,
    /// Explicit first-increment Wrapper seal: no Shamir fallback or recovery-key API.
    #[serde(default)]
    pub seal_barrier: bool,
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
}

impl fmt::Debug for OpenBaoWrapperConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoWrapperConfig([REDACTED])")
    }
}

fn default_startup_timeout_ms() -> u64 {
    2_000
}

fn absolute_regular_path(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 4096
        && path.file_name().is_some()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn digest(value: &str) -> Result<[u8; 32], BridgeError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BridgeError::InvalidBinding);
    }
    let mut bytes = [0; 32];
    for (slot, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let text = std::str::from_utf8(pair).map_err(|_| BridgeError::InvalidBinding)?;
        *slot = u8::from_str_radix(text, 16).map_err(|_| BridgeError::InvalidBinding)?;
    }
    if bytes == [0; 32] {
        return Err(BridgeError::InvalidBinding);
    }
    Ok(bytes)
}

impl OpenBaoWrapperConfig {
    fn validate(&self) -> Result<(), BridgeError> {
        if !absolute_regular_path(&self.command)
            || !absolute_regular_path(&self.configuration_file)
            || self.command == self.configuration_file
            || !(1..=10_000).contains(&self.startup_timeout_ms)
        {
            return Err(BridgeError::InvalidBinding);
        }
        match (&self.soft_hsm_configuration_file, &self.soft_hsm_configuration_sha256) {
            (None, None) => {}
            (Some(path), Some(hash)) if absolute_regular_path(path)
                && path != &self.command && path != &self.configuration_file => { digest(hash)?; }
            _ => return Err(BridgeError::InvalidBinding),
        }
        digest(&self.command_sha256)?;
        digest(&self.configuration_sha256)?;
        Ok(())
    }
}

#[derive(Debug)]
struct LifecycleState {
    generation: u64,
    revoked: bool,
    sealed: bool,
    #[cfg(target_os = "linux")]
    runtime: Option<linux::WrapperRuntime>,
    #[cfg(target_os = "linux")]
    cleanup: Option<Arc<Mutex<WrapperCleanupState>>>,
    #[cfg(target_os = "linux")]
    diagnostic: Option<Arc<Mutex<Option<serde_json::Value>>>>,
}

/// This hook is created by Service, never reconstructed from a PID or endpoint.
#[derive(Clone, Debug)]
struct ServiceLifecycle(Arc<Mutex<LifecycleState>>);

impl ServiceLifecycle {
    fn snapshot(&self) -> Result<HostLifecycle, BridgeError> {
        let state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked || state.generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        Ok(HostLifecycle {
            sealed: state.sealed,
            configuration_generation: state.generation,
        })
    }

    fn new(generation: u64) -> Self {
        Self(Arc::new(Mutex::new(LifecycleState {
            generation,
            revoked: false,
            sealed: true,
            #[cfg(target_os = "linux")]
            runtime: None,
            #[cfg(target_os = "linux")]
            cleanup: None,
            #[cfg(target_os = "linux")]
            diagnostic: None,
        })))
    }

    fn revoke(&self) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.revoked = true;
        state.generation = 0;
        state.sealed = true;
        #[cfg(target_os = "linux")]
        if let Some(runtime) = state.runtime.take() {
            runtime.revoke();
        }
    }

    #[cfg(target_os = "linux")]
    fn publish(&self, runtime: linux::WrapperRuntime) -> Result<(), BridgeError> {
        let mut state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked
            || state.generation == 0
            || !state.sealed
            || state.runtime.is_some()
            || runtime.generation() != state.generation
            || !runtime.is_live()
        {
            return Err(BridgeError::LifecycleDenied);
        }
        state.runtime = Some(runtime);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn track_diagnostic(&self, diagnostic: Arc<Mutex<Option<serde_json::Value>>>) -> Result<(), BridgeError> {
        let mut state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked || state.generation == 0 || state.diagnostic.is_some() {
            return Err(BridgeError::LifecycleDenied);
        }
        state.diagnostic = Some(diagnostic);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn track_cleanup(&self, cleanup: Arc<Mutex<WrapperCleanupState>>) -> Result<(), BridgeError> {
        let mut state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked || state.generation == 0 || state.cleanup.is_some() {
            return Err(BridgeError::LifecycleDenied);
        }
        state.cleanup = Some(cleanup);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn authorize_start(&self, generation: u64) -> Result<(), BridgeError> {
        let state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked || !state.sealed || state.generation != generation || generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        let cleanup = state.cleanup.as_ref().ok_or(BridgeError::InvalidState)?;
        let mut cleanup = cleanup.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if *cleanup != WrapperCleanupState::NotStarted {
            return Err(BridgeError::InvalidState);
        }
        *cleanup = WrapperCleanupState::Starting;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn retire_for_replacement(&self) -> Result<(), BridgeError> {
        // The same lock orders retirement against authorize_start. A worker
        // retired in NotStarted cannot cross the later Child creation gate.
        let mut state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        state.revoked = true;
        state.generation = 0;
        state.sealed = true;
        if let Some(runtime) = state.runtime.take() {
            runtime.revoke();
        }
        let cleanup = state
            .cleanup
            .as_ref()
            .map(|monitor| monitor.lock().map(|state| *state))
            .transpose()
            .map_err(|_| BridgeError::LifecycleDenied)?;
        match cleanup {
            None | Some(WrapperCleanupState::NotStarted | WrapperCleanupState::TerminalReaped) => {
                Ok(())
            }
            _ => Err(BridgeError::ProcessObservationUnavailable),
        }
    }

    #[cfg(target_os = "linux")]
    fn runtime(&self) -> Result<linux::WrapperRuntime, BridgeError> {
        let state = self.0.lock().map_err(|_| BridgeError::LifecycleDenied)?;
        if state.revoked || state.generation == 0 {
            return Err(BridgeError::LifecycleDenied);
        }
        state
            .runtime
            .clone()
            .filter(|runtime| runtime.is_live())
            .ok_or(BridgeError::InvalidState)
    }
}

#[cfg(target_os = "linux")]
impl heptabao_openbao_grpc::linux_identity::AuthoritativeLifecycleHook for ServiceLifecycle {
    fn snapshot(&self) -> Result<HostLifecycle, BridgeError> {
        self.snapshot()
    }
}

/// A single-use startup plan; execution happens after releasing the Service lock.
/// Successful execution publishes a retained runtime into this exact generation.
/// No plaintext or barrier key is returned by startup admission.
pub struct OpenBaoWrapperLaunchPlan {
    config: OpenBaoWrapperConfig,
    lifecycle: ServiceLifecycle,
    #[cfg(target_os = "linux")]
    runtime_directory: PathBuf,
}

impl fmt::Debug for OpenBaoWrapperLaunchPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoWrapperLaunchPlan([REDACTED])")
    }
}

impl OpenBaoWrapperLaunchPlan {
    pub fn execute(self) -> Result<(), BridgeError> {
        self.config.validate()?;
        self.lifecycle.snapshot()?;
        #[cfg(target_os = "linux")]
        let result = linux::launch_automatic_runtime(
            &self.config,
            self.lifecycle.clone(),
            self.runtime_directory,
        )
        .and_then(|runtime| self.lifecycle.publish(runtime));
        #[cfg(not(target_os = "linux"))]
        let result = Err(BridgeError::ProcessObservationUnavailable);
        if result.is_err() {
            self.lifecycle.revoke();
        }
        result
    }
}

pub(super) struct ServiceWrapperOwner {
    lifecycle: ServiceLifecycle,
    #[cfg(target_os = "linux")]
    barrier_binding: Option<[u8; 32]>,
    #[cfg(target_os = "linux")]
    barrier_initialization_claimed: std::sync::atomic::AtomicBool,
}

pub(super) fn fence(owner: &Option<ServiceWrapperOwner>) {
    if let Some(owner) = owner.as_ref() {
        owner.revoke();
    }
}

impl ServiceWrapperOwner {
    pub(super) fn revoke(&self) {
        self.lifecycle.revoke();
    }
}

impl Drop for ServiceWrapperOwner {
    fn drop(&mut self) {
        self.revoke();
    }
}

impl Service {
    /// Replacement/removal invalidates all old startup plans. Configuration is
    /// process-owned and immutable while unsealed or in recovery.
    pub fn install_openbao_wrapper(
        &mut self,
        config: Option<OpenBaoWrapperConfig>,
    ) -> Result<Option<OpenBaoWrapperLaunchPlan>, String> {
        // The absent opt-in leaves every legacy startup/recovery path intact.
        if config.is_none() && self.openbao_wrapper_owner.is_none() {
            return Ok(None);
        }
        if self.state.is_some() || self.recovery_required {
            return Err("Wrapper configuration requires a sealed non-recovery service".into());
        }
        if let Some(config) = config.as_ref() {
            config.validate().map_err(|error| error.to_string())?;
        }
        let barrier_binding = config.as_ref().filter(|config| config.seal_barrier)
            .map(|config| barrier::configuration_binding(config, &self.data_dir))
            .transpose().map_err(|error| error.to_string())?;
        if let Some(seal) = self.seal.as_ref() {
            if seal.schema == 2 {
                let envelope = barrier::Envelope::decode(&seal.wrapped_barrier_key)
                    .map_err(|_| "Wrapper seal envelope is invalid")?;
                if barrier_binding != Some(envelope.binding()?) {
                    return Err("Wrapper seal requires its exact deployment configuration".into());
                }
            } else if barrier_binding.is_some() {
                return Err("existing local seal requires explicit future migration".into());
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(owner) = self.openbao_wrapper_owner.as_ref() {
            owner
                .lifecycle
                .retire_for_replacement()
                .map_err(|_| "Wrapper replacement requires observed terminal cleanup".to_owned())?;
        }
        self.openbao_wrapper_owner = None;
        self.openbao_wrapper_generation = self
            .openbao_wrapper_generation
            .checked_add(1)
            .ok_or_else(|| "Wrapper configuration generation exhausted".to_owned())?;
        let Some(config) = config else {
            return Ok(None);
        };
        let lifecycle = ServiceLifecycle::new(self.openbao_wrapper_generation);
        #[cfg(target_os = "linux")]
        let runtime_directory = {
            let suffix = super::crypto::random::<16>()
                .map_err(|_| "Wrapper launch identity unavailable".to_owned())?;
            self.data_dir.parent()
                .ok_or("Wrapper data directory has no parent")?
                .join(format!(".heptabao-wrapper-launch-{}", super::hex(&suffix)))
        };
        self.openbao_wrapper_owner = Some(ServiceWrapperOwner {
            lifecycle: lifecycle.clone(),
            #[cfg(target_os = "linux")]
            barrier_binding,
            #[cfg(target_os = "linux")]
            barrier_initialization_claimed: std::sync::atomic::AtomicBool::new(false),
        });
        Ok(Some(OpenBaoWrapperLaunchPlan {
            config,
            lifecycle,
            #[cfg(target_os = "linux")]
            runtime_directory,
        }))
    }

    pub(super) fn fence_openbao_wrapper(&self) {
        fence(&self.openbao_wrapper_owner);
    }
}

/// Activating storage preserves an already admitted generation only after the
/// actual activation publication succeeds. Every early return revokes it.
pub(super) struct WrapperActivation {
    lifecycle: Option<ServiceLifecycle>,
    required: bool,
    completed: bool,
}
impl WrapperActivation {
    pub(super) fn publish_unsealed(mut self) -> Result<(), BridgeError> {
        if self.required && self.lifecycle.is_none() {
            return Err(BridgeError::LifecycleDenied);
        }
        if let Some(lifecycle) = self.lifecycle.as_ref() {
            let mut state = lifecycle
                .0
                .lock()
                .map_err(|_| BridgeError::LifecycleDenied)?;
            if state.revoked || state.generation == 0 || !state.sealed {
                return Err(BridgeError::LifecycleDenied);
            }
            #[cfg(target_os = "linux")]
            if !state
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.is_live())
            {
                return Err(BridgeError::LifecycleDenied);
            }
            state.sealed = false;
        }
        self.completed = true;
        Ok(())
    }
}
impl Drop for WrapperActivation {
    fn drop(&mut self) {
        if !self.completed
            && let Some(lifecycle) = self.lifecycle.as_ref()
        {
            lifecycle.revoke();
        }
    }
}
impl Service {
    pub(super) fn begin_openbao_wrapper_activation(&self) -> WrapperActivation {
        let required = self.seal.as_ref().is_some_and(|seal| seal.schema == 2);
        let lifecycle = self
            .openbao_wrapper_owner
            .as_ref()
            .map(|owner| owner.lifecycle.clone());
        #[cfg(target_os = "linux")]
        let admitted = lifecycle
            .as_ref()
            .is_some_and(|lifecycle| lifecycle.runtime().is_ok());
        #[cfg(not(target_os = "linux"))]
        let admitted = false;
        if !admitted {
            if let Some(lifecycle) = lifecycle.as_ref() {
                lifecycle.revoke();
            }
            return WrapperActivation {
                lifecycle: None,
                required,
                completed: false,
            };
        }
        WrapperActivation {
            lifecycle,
            required,
            completed: false,
        }
    }
}

#[cfg(target_os = "linux")]
pub struct OpenBaoWrapperOperationPlan {
    lifecycle: ServiceLifecycle,
    observation: HostLifecycle,
    runtime: linux::WrapperRuntime,
    operation: WrapperOperation,
    deadline: Instant,
}
#[cfg(target_os = "linux")]
impl fmt::Debug for OpenBaoWrapperOperationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoWrapperOperationPlan([REDACTED])")
    }
}
#[cfg(target_os = "linux")]
pub struct OpenBaoWrapperCompletion {
    lifecycle: ServiceLifecycle,
    observation: HostLifecycle,
    result: Result<WrapperReply, BridgeError>,
    deadline: Instant,
}
#[cfg(target_os = "linux")]
impl fmt::Debug for OpenBaoWrapperCompletion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenBaoWrapperCompletion([REDACTED])")
    }
}
#[cfg(target_os = "linux")]
impl OpenBaoWrapperOperationPlan {
    /// This must execute outside the Service writer lock. A dispatched failure
    /// revokes the runtime and is never retried against another session.
    pub fn execute(self) -> OpenBaoWrapperCompletion {
        let result = self.runtime.execute(self.operation, self.deadline);
        OpenBaoWrapperCompletion {
            lifecycle: self.lifecycle,
            observation: self.observation,
            result,
            deadline: self.deadline,
        }
    }
}
#[cfg(target_os = "linux")]
impl Service {
    /// Trusted native consumer API. No HTTP route exposes this capability.
    pub fn openbao_wrapper_cleanup_state(&self) -> Option<WrapperCleanupState> {
        let owner = self.openbao_wrapper_owner.as_ref()?;
        let state = owner.lifecycle.0.lock().ok()?;
        state.cleanup.as_ref().map(|monitor| {
            monitor
                .lock()
                .map(|state| *state)
                .unwrap_or(WrapperCleanupState::CleanupUnknown)
        })
    }
    pub(crate) fn openbao_wrapper_private_observation(&self) -> Result<serde_json::Value, String> {
        let owner = self.openbao_wrapper_owner.as_ref().ok_or("Wrapper observation owner missing")?;
        let state = owner.lifecycle.0.lock().map_err(|_| "Wrapper observation owner unavailable")?;
        let mut observation = match state.diagnostic.as_ref() {
            Some(monitor) => monitor.lock().map_err(|_| "Wrapper admission observation unavailable")?
                .clone().ok_or("Wrapper admission observation incomplete")?,
            None => serde_json::json!({"provider":null,"owned_pid":null,"generation":self.openbao_wrapper_generation,
                "authenticated_h2":false,"health_authenticated":false}),
        };
        let cleanup = match state.cleanup.as_ref() {
            Some(monitor) => *monitor.lock().map_err(|_| "Wrapper cleanup monitor unavailable")?,
            None => WrapperCleanupState::NotStarted,
        };
        observation["cleanup"] = serde_json::json!(format!("{cleanup:?}"));
        observation["sealed"] = serde_json::json!(self.state.is_none() && self.barrier_key.is_none());
        Ok(observation)
    }
    pub fn prepare_openbao_wrapper_operation(
        &self,
        operation: WrapperOperation,
    ) -> Result<OpenBaoWrapperOperationPlan, BridgeError> {
        if self.recovery_required {
            return Err(BridgeError::LifecycleDenied);
        }
        let lifecycle = self
            .openbao_wrapper_owner
            .as_ref()
            .ok_or(BridgeError::InvalidState)?
            .lifecycle
            .clone();
        let observation = lifecycle.snapshot()?;
        if observation.sealed != self.state.is_none() {
            return Err(BridgeError::LifecycleDenied);
        }
        let runtime = lifecycle.runtime()?;
        let deadline = Instant::now() + runtime.timeout();
        let deadline = crate::request_deadline::current().map_or(deadline, |request| request.min(deadline));
        if Instant::now() >= deadline {
            return Err(BridgeError::BeforeDispatch);
        }
        Ok(OpenBaoWrapperOperationPlan {
            lifecycle,
            observation,
            runtime,
            operation,
            deadline,
        })
    }
    pub fn finish_openbao_wrapper_operation(
        &self,
        completion: OpenBaoWrapperCompletion,
    ) -> Result<WrapperReply, BridgeError> {
        if Instant::now() >= completion.deadline {
            completion.lifecycle.revoke();
            return Err(BridgeError::OutcomeUnknown);
        }
        if self.recovery_required
            || !self
                .openbao_wrapper_owner
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(&owner.lifecycle.0, &completion.lifecycle.0))
            || completion.lifecycle.snapshot()? != completion.observation
            || completion.observation.sealed != self.state.is_none()
            || completion.lifecycle.runtime().is_err()
        {
            return Err(BridgeError::LifecycleDenied);
        }
        completion.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_has_no_endpoint_material_or_protocol_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = serde_json::json!({
            "command": "/owned/provider", "command_sha256": "11".repeat(32),
            "configuration_file": "/owned/config.json", "configuration_sha256": "22".repeat(32),
            "transport": "auto_mtls"
        });
        let config: OpenBaoWrapperConfig = serde_json::from_value(value.clone())?;
        config.validate()?;
        value["endpoint"] = "https://127.0.0.1:1".into();
        assert!(serde_json::from_value::<OpenBaoWrapperConfig>(value.clone()).is_err());
        let object = value.as_object_mut().ok_or("expected object")?;
        object.remove("endpoint");
        object.insert("transport".into(), "plaintext".into());
        assert!(serde_json::from_value::<OpenBaoWrapperConfig>(value).is_err());
        let mut invalid = config.clone();
        invalid.command = PathBuf::from("/owned/../provider");
        assert!(invalid.validate().is_err());
        invalid = config;
        invalid.configuration_sha256 = "00".repeat(32);
        assert!(invalid.validate().is_err());
        Ok(())
    }

    #[test]
    fn owner_drop_and_revoke_invalidate_captured_generation() -> Result<(), BridgeError> {
        let lifecycle = ServiceLifecycle::new(7);
        let before = lifecycle.snapshot()?;
        assert!(before.sealed);
        assert_eq!(before.configuration_generation, 7);
        let owner = ServiceWrapperOwner {
            lifecycle: lifecycle.clone(),
            #[cfg(target_os = "linux")]
            barrier_binding: None,
            #[cfg(target_os = "linux")]
            barrier_initialization_claimed: std::sync::atomic::AtomicBool::new(false),
        };
        drop(owner);
        assert_eq!(lifecycle.snapshot(), Err(BridgeError::LifecycleDenied));
        lifecycle.revoke();
        assert_eq!(lifecycle.snapshot(), Err(BridgeError::LifecycleDenied));
        Ok(())
    }

    #[test]
    fn replacement_removal_drop_and_unseal_fence_before_process_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = super::super::tests::Root::new();
        let mut service = root.service()?;
        let config: OpenBaoWrapperConfig = serde_json::from_value(serde_json::json!({
            "command": "/missing/owned/provider", "command_sha256": "11".repeat(32),
            "configuration_file": "/missing/owned/config.json", "configuration_sha256": "22".repeat(32),
            "transport": "auto_mtls"
        }))?;
        let first = service
            .install_openbao_wrapper(Some(config.clone()))?
            .ok_or("plan")?;
        let generation = first.lifecycle.snapshot()?.configuration_generation;
        let second = service
            .install_openbao_wrapper(Some(config.clone()))?
            .ok_or("plan")?;
        assert!(second.lifecycle.snapshot()?.configuration_generation > generation);
        assert_eq!(first.execute(), Err(BridgeError::LifecycleDenied));
        service.install_openbao_wrapper(None)?;
        assert_eq!(second.execute(), Err(BridgeError::LifecycleDenied));
        let third = service
            .install_openbao_wrapper(Some(config.clone()))?
            .ok_or("plan")?;
        // A real activation entry revokes before storage or cryptographic work.
        let _ = service.activate_barrier(&crate::test_support::random_bytes());
        assert_eq!(third.execute(), Err(BridgeError::LifecycleDenied));
        let second_root = super::super::tests::Root::new();
        let mut second_service = second_root.service()?;
        let fourth = second_service
            .install_openbao_wrapper(Some(config))?
            .ok_or("plan")?;
        drop(second_service);
        assert_eq!(fourth.execute(), Err(BridgeError::LifecycleDenied));
        Ok(())
    }

    #[test]
    fn required_wrapper_activation_cannot_publish_without_admitted_owner() {
        let activation = WrapperActivation { lifecycle: None, required: true, completed: false };
        assert_eq!(activation.publish_unsealed(), Err(BridgeError::LifecycleDenied));
    }

    #[test]
    fn activation_publication_changes_only_the_current_generation() -> Result<(), BridgeError> {
        let lifecycle = ServiceLifecycle::new(9);
        let activation = WrapperActivation {
            lifecycle: Some(lifecycle.clone()),
            required: false,
            completed: false,
        };
        assert!(lifecycle.snapshot()?.sealed);
        #[cfg(not(target_os = "linux"))]
        {
            activation.publish_unsealed()?;
            assert_eq!(
                lifecycle.snapshot()?,
                HostLifecycle {
                    sealed: false,
                    configuration_generation: 9
                }
            );
        }
        #[cfg(target_os = "linux")]
        {
            // No retained live runtime: the storage activation publication
            // must not turn a configured but unadmitted owner into authority.
            assert_eq!(
                activation.publish_unsealed(),
                Err(BridgeError::LifecycleDenied)
            );
            assert_eq!(lifecycle.snapshot(), Err(BridgeError::LifecycleDenied));
        }
        lifecycle.revoke();
        assert_eq!(lifecycle.snapshot(), Err(BridgeError::LifecycleDenied));
        let abandoned = ServiceLifecycle::new(10);
        drop(WrapperActivation {
            lifecycle: Some(abandoned.clone()),
            required: false,
            completed: false,
        });
        assert_eq!(abandoned.snapshot(), Err(BridgeError::LifecycleDenied));
        let fenced = ServiceLifecycle::new(11);
        let captured = WrapperActivation {
            lifecycle: Some(fenced.clone()),
            required: false,
            completed: false,
        };
        fenced.revoke();
        assert_eq!(
            captured.publish_unsealed(),
            Err(BridgeError::LifecycleDenied)
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retirement_orders_child_start_and_keeps_unknown_cleanup_pending() -> Result<(), BridgeError>
    {
        let before_start = ServiceLifecycle::new(12);
        let monitor = Arc::new(Mutex::new(WrapperCleanupState::NotStarted));
        before_start.track_cleanup(monitor.clone())?;
        before_start.retire_for_replacement()?;
        assert_eq!(
            before_start.authorize_start(12),
            Err(BridgeError::LifecycleDenied)
        );
        assert_eq!(
            *monitor.lock().map_err(|_| BridgeError::InvalidState)?,
            WrapperCleanupState::NotStarted
        );

        let starting = ServiceLifecycle::new(13);
        let monitor = Arc::new(Mutex::new(WrapperCleanupState::NotStarted));
        starting.track_cleanup(monitor.clone())?;
        starting.authorize_start(13)?;
        assert_eq!(
            *monitor.lock().map_err(|_| BridgeError::InvalidState)?,
            WrapperCleanupState::Starting
        );
        assert_eq!(
            starting.retire_for_replacement(),
            Err(BridgeError::ProcessObservationUnavailable)
        );
        for state in [
            WrapperCleanupState::Live,
            WrapperCleanupState::StopRequested,
            WrapperCleanupState::CleanupUnknown,
        ] {
            *monitor.lock().map_err(|_| BridgeError::InvalidState)? = state;
            assert_eq!(
                starting.retire_for_replacement(),
                Err(BridgeError::ProcessObservationUnavailable)
            );
        }
        *monitor.lock().map_err(|_| BridgeError::InvalidState)? =
            WrapperCleanupState::TerminalReaped;
        starting.retire_for_replacement()?;
        Ok(())
    }

    #[test]
    fn absent_wrapper_is_a_noop_during_existing_recovery() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = super::super::tests::Root::new();
        let mut service = root.service()?;
        service.recovery_required = true;
        assert!(service.install_openbao_wrapper(None)?.is_none());
        assert!(service.openbao_wrapper_owner.is_none());
        assert_eq!(service.openbao_wrapper_generation, 0);
        Ok(())
    }
}
