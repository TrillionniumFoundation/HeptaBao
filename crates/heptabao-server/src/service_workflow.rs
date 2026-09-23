//! The deliberately small, server-owned workflow/profile contract.
//!
//! This module contains only data admission, ownership binding and digest
//! helpers. Execution remains in `service.rs`, where the normal authenticated
//! request pipeline and durable commit boundary are available. This is not a
//! scripting or plugin runtime.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const MAX_PROFILES: usize = 64;
pub const MAX_STEPS: usize = 32;
pub const MAX_TEXT: usize = 256;
pub const MAX_RUNS: usize = 256;
pub const MAX_STEP_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_TOTAL_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_RUNTIME_MILLIS: u128 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct WorkflowState {
    pub profiles: Vec<WorkflowProfile>,
    pub runs: Vec<WorkflowRun>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowProfile {
    #[serde(default)]
    pub namespace: String,
    pub name: String,
    pub revision: u64,
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowStep {
    pub id: String,
    pub depends_on: Vec<String>,
    pub operation: WorkflowOperation,
    pub target: String,
    pub secret_output: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowOperation {
    #[serde(alias = "kv_read")]
    KvRead,
    #[serde(alias = "kv_write")]
    KvWrite,
    /// Retained as a model-level compatibility sentinel for the original
    /// review scaffold. The server does not execute it: outbound actions need
    /// a separately registered, typed implementation.
    OutboundNamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRun {
    pub id: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub profile_name: String,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub principal_digest: [u8; 32],
    pub binding_digest: [u8; 32],
    #[serde(default)]
    pub operation_digest: [u8; 32],
    pub phase: RunPhase,
    #[serde(default)]
    pub completed_steps: Vec<String>,
    #[serde(default)]
    pub active_step: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunPhase {
    Pending,
    Running,
    Succeeded,
    ReconcileRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunSummary {
    pub id: String,
    pub binding_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub phase: RunPhase,
    pub completed_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBinding {
    principal_digest: [u8; 32],
    namespace: String,
    profile_name: String,
    profile_revision: u64,
    request_id: String,
    digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowError {
    TooManyProfiles,
    TooManyRuns,
    TooManySteps,
    TextTooLong(&'static str),
    EmptyText(&'static str),
    DuplicateProfile,
    DuplicateStep,
    MissingDependency,
    Cycle,
    InvalidEndpoint,
    InvalidTarget,
    InvalidRevision,
    InvalidPayload,
    PayloadTooLarge,
    DuplicateRun,
    InvalidTransition,
    #[cfg(test)]
    DigestMismatch,
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for WorkflowError {}

impl WorkflowState {
    pub fn validate(&self) -> Result<(), WorkflowError> {
        if self.profiles.len() > MAX_PROFILES {
            return Err(WorkflowError::TooManyProfiles);
        }
        if self.runs.len() > MAX_RUNS {
            return Err(WorkflowError::TooManyRuns);
        }
        let mut profile_names = HashSet::new();
        for profile in &self.profiles {
            profile.validate()?;
            if !profile_names.insert((&profile.namespace, &profile.name)) {
                return Err(WorkflowError::DuplicateProfile);
            }
        }
        let mut run_ids = HashSet::new();
        for run in &self.runs {
            validate_text(&run.id, "run id")?;
            validate_namespace(&run.namespace)?;
            validate_text(&run.profile_name, "profile name")?;
            validate_text(&run.request_id, "request id")?;
            if !run_ids.insert(&run.id) {
                return Err(WorkflowError::DuplicateRun);
            }
            if run.completed_steps.len() > MAX_STEPS {
                return Err(WorkflowError::TooManySteps);
            }
            if run.completed_steps.iter().any(|step| step.is_empty()) {
                return Err(WorkflowError::InvalidPayload);
            }
            if let Some(active) = &run.active_step {
                validate_text(active, "active step")?;
            }
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.runs.is_empty()
    }

    pub fn profile(&self, namespace: &str, name: &str) -> Option<&WorkflowProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.namespace == namespace && profile.name == name)
    }

    pub fn profile_mut(&mut self, namespace: &str, name: &str) -> Option<&mut WorkflowProfile> {
        self.profiles
            .iter_mut()
            .find(|profile| profile.namespace == namespace && profile.name == name)
    }

    pub fn run(&self, id: &str) -> Option<&WorkflowRun> {
        self.runs.iter().find(|run| run.id == id)
    }

    pub fn run_mut(&mut self, id: &str) -> Option<&mut WorkflowRun> {
        self.runs.iter_mut().find(|run| run.id == id)
    }

    /// A process can die after an internal effect but before its completion
    /// marker is committed. On reopen, never infer success and never replay
    /// the step. The durable record becomes explicitly reconcilable instead.
    pub fn recover_inflight(&mut self) -> bool {
        let mut changed = false;
        for run in &mut self.runs {
            if run.phase == RunPhase::Running {
                run.phase = RunPhase::ReconcileRequired;
                changed = true;
            }
        }
        changed
    }
}

impl WorkflowProfile {
    pub fn validate(&self) -> Result<(), WorkflowError> {
        validate_namespace(&self.namespace)?;
        validate_text(&self.name, "profile name")?;
        if self.revision == 0 {
            return Err(WorkflowError::InvalidRevision);
        }
        validate_steps(&self.steps)
    }
}

impl RunBinding {
    pub fn new(
        principal_digest: [u8; 32],
        namespace: impl Into<String>,
        profile_name: impl Into<String>,
        profile_revision: u64,
        request_id: impl Into<String>,
    ) -> Result<Self, WorkflowError> {
        let namespace = namespace.into();
        let profile_name = profile_name.into();
        let request_id = request_id.into();
        validate_namespace(&namespace)?;
        validate_text(&profile_name, "profile name")?;
        validate_text(&request_id, "request id")?;
        let digest = binding_digest(
            principal_digest,
            &namespace,
            &profile_name,
            profile_revision,
            &request_id,
        );
        Ok(Self {
            principal_digest,
            namespace,
            profile_name,
            profile_revision,
            request_id,
            digest,
        })
    }

    pub fn new_with_operation(
        principal_digest: [u8; 32],
        namespace: impl Into<String>,
        profile_name: impl Into<String>,
        profile_revision: u64,
        request_id: impl Into<String>,
        operation_digest: [u8; 32],
    ) -> Result<Self, WorkflowError> {
        let mut binding = Self::new(
            principal_digest,
            namespace,
            profile_name,
            profile_revision,
            request_id,
        )?;
        binding.digest = binding_digest_with_operation(
            binding.principal_digest,
            binding.namespace(),
            binding.profile_name(),
            binding.profile_revision(),
            binding.request_id(),
            operation_digest,
        );
        Ok(binding)
    }

    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn profile_revision(&self) -> u64 {
        self.profile_revision
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl WorkflowRun {
    pub fn new(id: impl Into<String>, binding: &RunBinding) -> Result<Self, WorkflowError> {
        let id = id.into();
        validate_text(&id, "run id")?;
        Ok(Self {
            id,
            namespace: binding.namespace.clone(),
            profile_name: binding.profile_name.clone(),
            request_id: binding.request_id.clone(),
            principal_digest: binding.principal_digest,
            binding_digest: binding.digest(),
            operation_digest: [0; 32],
            phase: RunPhase::Pending,
            completed_steps: Vec::new(),
            active_step: None,
        })
    }

    pub fn new_with_operation(
        id: impl Into<String>,
        binding: &RunBinding,
        operation_digest: [u8; 32],
    ) -> Result<Self, WorkflowError> {
        let mut run = Self::new(id, binding)?;
        run.operation_digest = operation_digest;
        Ok(run)
    }

    pub fn transition(&mut self, next: RunPhase) -> Result<(), WorkflowError> {
        let allowed = matches!(
            (&self.phase, &next),
            (RunPhase::Pending, RunPhase::Running)
                | (RunPhase::Running, RunPhase::Succeeded)
                | (RunPhase::Running, RunPhase::Failed)
                | (RunPhase::Running, RunPhase::ReconcileRequired)
                | (RunPhase::ReconcileRequired, RunPhase::Pending)
        );
        if allowed {
            self.phase = next;
            Ok(())
        } else {
            Err(WorkflowError::InvalidTransition)
        }
    }

    #[cfg(test)]
    pub fn reconcile_to_pending(&mut self, expected_digest: [u8; 32]) -> Result<(), WorkflowError> {
        if self.phase != RunPhase::ReconcileRequired {
            return Err(WorkflowError::InvalidTransition);
        }
        if self.binding_digest != expected_digest {
            return Err(WorkflowError::DigestMismatch);
        }
        self.phase = RunPhase::Pending;
        Ok(())
    }

    pub fn owner_matches(&self, principal_digest: [u8; 32], namespace: &str) -> bool {
        self.principal_digest == principal_digest && self.namespace == namespace
    }
}

pub fn operation_digest(
    namespace: &str,
    profile: &WorkflowProfile,
    values: &BTreeMap<String, Value>,
) -> Result<[u8; 32], WorkflowError> {
    let encoded = serde_json::to_vec(&(namespace, profile, values))
        .map_err(|_| WorkflowError::InvalidPayload)?;
    if encoded.len() > MAX_TOTAL_PAYLOAD_BYTES + MAX_TEXT * MAX_STEPS {
        return Err(WorkflowError::PayloadTooLarge);
    }
    Ok(Sha256::digest(&encoded).into())
}

pub fn validate_payloads(values: &BTreeMap<String, Value>) -> Result<usize, WorkflowError> {
    let mut total = 0usize;
    for value in values.values() {
        let encoded = serde_json::to_vec(value).map_err(|_| WorkflowError::InvalidPayload)?;
        if encoded.len() > MAX_STEP_PAYLOAD_BYTES {
            return Err(WorkflowError::PayloadTooLarge);
        }
        total = total
            .checked_add(encoded.len())
            .ok_or(WorkflowError::PayloadTooLarge)?;
        if total > MAX_TOTAL_PAYLOAD_BYTES {
            return Err(WorkflowError::PayloadTooLarge);
        }
    }
    Ok(total)
}

fn validate_steps(steps: &[WorkflowStep]) -> Result<(), WorkflowError> {
    if steps.len() > MAX_STEPS {
        return Err(WorkflowError::TooManySteps);
    }
    let mut ids = HashSet::new();
    for step in steps {
        validate_text(&step.id, "step id")?;
        validate_text(&step.target, "step target")?;
        if !ids.insert(&step.id) {
            return Err(WorkflowError::DuplicateStep);
        }
        if step.depends_on.len() > MAX_STEPS {
            return Err(WorkflowError::TooManySteps);
        }
        for dependency in &step.depends_on {
            validate_text(dependency, "dependency id")?;
            if !ids.contains(dependency)
                && !steps.iter().any(|candidate| candidate.id == *dependency)
            {
                return Err(WorkflowError::MissingDependency);
            }
        }
        match step.operation {
            WorkflowOperation::KvRead | WorkflowOperation::KvWrite => {
                if !is_internal_target(&step.target) {
                    return Err(WorkflowError::InvalidTarget);
                }
            }
            WorkflowOperation::OutboundNamed => {
                if !is_simple_endpoint(&step.target) {
                    return Err(WorkflowError::InvalidEndpoint);
                }
            }
        }
    }

    let edges: HashMap<&str, Vec<&str>> = steps
        .iter()
        .map(|step| {
            (
                step.id.as_str(),
                step.depends_on.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for id in edges.keys() {
        if has_cycle(id, &edges, &mut visiting, &mut visited) {
            return Err(WorkflowError::Cycle);
        }
    }
    Ok(())
}

fn has_cycle<'a>(
    id: &'a str,
    edges: &HashMap<&'a str, Vec<&'a str>>,
    visiting: &mut HashSet<&'a str>,
    visited: &mut HashSet<&'a str>,
) -> bool {
    if visiting.contains(id) {
        return true;
    }
    if visited.contains(id) {
        return false;
    }
    visiting.insert(id);
    if edges.get(id).is_some_and(|dependencies| {
        dependencies
            .iter()
            .any(|dependency| has_cycle(dependency, edges, visiting, visited))
    }) {
        return true;
    }
    visiting.remove(id);
    visited.insert(id);
    false
}

fn validate_text(value: &str, field: &'static str) -> Result<(), WorkflowError> {
    if value.is_empty() {
        return Err(WorkflowError::EmptyText(field));
    }
    if value.chars().count() > MAX_TEXT {
        return Err(WorkflowError::TextTooLong(field));
    }
    Ok(())
}

fn validate_namespace(value: &str) -> Result<(), WorkflowError> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > MAX_TEXT
        || value.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(WorkflowError::InvalidTarget);
    }
    Ok(())
}

fn is_internal_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && !value.starts_with('/')
        && !value.contains("//")
        && !value.contains('?')
        && !value.contains('#')
        && !value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        && !value.starts_with("sys/")
        && !value.starts_with("auth/")
        && !value.starts_with("identity/")
        && !value.starts_with("cubbyhole/")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':')
        })
}

fn is_simple_endpoint(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn binding_digest(
    principal_digest: [u8; 32],
    namespace: &str,
    profile_name: &str,
    profile_revision: u64,
    request_id: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"heptabao.workflow.run-binding.v1\0");
    hasher.update(principal_digest);
    for field in [
        namespace.as_bytes(),
        profile_name.as_bytes(),
        request_id.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher.update(profile_revision.to_be_bytes());
    hasher.finalize().into()
}

fn binding_digest_with_operation(
    principal_digest: [u8; 32],
    namespace: &str,
    profile_name: &str,
    profile_revision: u64,
    request_id: &str,
    operation_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"heptabao.workflow.run-binding.v2\0");
    hasher.update(binding_digest(
        principal_digest,
        namespace,
        profile_name,
        profile_revision,
        request_id,
    ));
    hasher.update(operation_digest);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn step(
        id: &str,
        depends_on: &[&str],
        operation: WorkflowOperation,
        target: &str,
    ) -> WorkflowStep {
        WorkflowStep {
            id: id.into(),
            depends_on: depends_on.iter().map(|value| (*value).into()).collect(),
            operation,
            target: target.into(),
            secret_output: false,
        }
    }

    fn profile(steps: Vec<WorkflowStep>) -> WorkflowProfile {
        WorkflowProfile {
            namespace: String::new(),
            name: "p".into(),
            revision: 1,
            steps,
        }
    }

    #[test]
    fn profile_bound() {
        let state = WorkflowState {
            profiles: (0..=MAX_PROFILES)
                .map(|i| WorkflowProfile {
                    namespace: String::new(),
                    name: format!("p{i}"),
                    revision: 1,
                    steps: vec![],
                })
                .collect(),
            runs: vec![],
        };
        assert_eq!(state.validate(), Err(WorkflowError::TooManyProfiles));
    }

    #[test]
    fn step_bound() {
        assert_eq!(
            profile(
                (0..=MAX_STEPS)
                    .map(|i| step(
                        &i.to_string(),
                        &[],
                        WorkflowOperation::KvRead,
                        "secret/data/k"
                    ))
                    .collect()
            )
            .validate(),
            Err(WorkflowError::TooManySteps)
        );
    }

    #[test]
    fn text_bound() {
        assert_eq!(
            profile(vec![step(
                &"x".repeat(MAX_TEXT + 1),
                &[],
                WorkflowOperation::KvRead,
                "secret/data/k"
            )])
            .validate(),
            Err(WorkflowError::TextTooLong("step id"))
        );
    }

    #[test]
    fn duplicate_ids() {
        assert_eq!(
            profile(vec![
                step("a", &[], WorkflowOperation::KvRead, "secret/data/k"),
                step("a", &[], WorkflowOperation::KvRead, "secret/data/k")
            ])
            .validate(),
            Err(WorkflowError::DuplicateStep)
        );
    }

    #[test]
    fn missing_dependency() {
        assert_eq!(
            profile(vec![step(
                "a",
                &["missing"],
                WorkflowOperation::KvRead,
                "secret/data/k"
            )])
            .validate(),
            Err(WorkflowError::MissingDependency)
        );
    }

    #[test]
    fn cycle_rejected() {
        assert_eq!(
            profile(vec![
                step("a", &["b"], WorkflowOperation::KvRead, "secret/data/k"),
                step("b", &["a"], WorkflowOperation::KvRead, "secret/data/k")
            ])
            .validate(),
            Err(WorkflowError::Cycle)
        );
    }

    #[test]
    fn endpoint_url_rejected() {
        assert_eq!(
            profile(vec![step(
                "a",
                &[],
                WorkflowOperation::OutboundNamed,
                "https://example.com"
            )])
            .validate(),
            Err(WorkflowError::InvalidEndpoint)
        );
    }

    #[test]
    fn endpoint_id_accepted() {
        assert!(
            profile(vec![step(
                "a",
                &[],
                WorkflowOperation::OutboundNamed,
                "svc_v1.prod-2"
            )])
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn namespace_changes_digest() {
        let a = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let b = RunBinding::new([1; 32], "other", "p", 1, "r").unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn revision_changes_digest_and_is_bound() {
        let a = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let b = RunBinding::new([1; 32], "n", "p", 2, "r").unwrap();
        assert_ne!(a.digest(), b.digest());
        assert_eq!(b.profile_revision(), 2);
    }

    #[test]
    fn ambiguous_retry_denied() {
        let binding = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let mut run = WorkflowRun::new("run", &binding).unwrap();
        run.transition(RunPhase::Running).unwrap();
        run.transition(RunPhase::ReconcileRequired).unwrap();
        assert_eq!(
            run.transition(RunPhase::Running),
            Err(WorkflowError::InvalidTransition)
        );
    }

    #[test]
    fn explicit_reconcile_allows_retry() {
        let binding = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let mut run = WorkflowRun::new("run", &binding).unwrap();
        run.transition(RunPhase::Running).unwrap();
        run.transition(RunPhase::ReconcileRequired).unwrap();
        run.reconcile_to_pending(binding.digest()).unwrap();
        assert_eq!(run.transition(RunPhase::Running), Ok(()));
    }

    #[test]
    fn wrong_reconcile_digest_denied() {
        let binding = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let mut run = WorkflowRun::new("run", &binding).unwrap();
        run.transition(RunPhase::Running).unwrap();
        run.transition(RunPhase::ReconcileRequired).unwrap();
        assert_eq!(
            run.reconcile_to_pending([2; 32]),
            Err(WorkflowError::DigestMismatch)
        );
    }

    #[test]
    fn serde_roundtrip() {
        let state = WorkflowState {
            profiles: vec![profile(vec![step(
                "a",
                &[],
                WorkflowOperation::KvRead,
                "secret/data/k",
            )])],
            runs: vec![],
        };
        let encoded = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serde_json::from_str::<WorkflowState>(&encoded).unwrap(),
            state
        );
    }

    #[test]
    fn summary_is_redacted() {
        let binding = RunBinding::new([1; 32], "n", "p", 1, "r").unwrap();
        let run = WorkflowRun::new("run", &binding).unwrap();
        let json = serde_json::to_string(&WorkflowState {
            profiles: vec![],
            runs: vec![run],
        })
        .unwrap();
        assert!(!json.contains("secret_output"));
    }

    #[test]
    fn hostile_targets_cannot_escape_the_internal_kv_surface() {
        for target in [
            "https://127.0.0.1/secret",
            "secret/data/../../outside",
            "secret/data/key?url=https://127.0.0.1",
            "sys/mounts/evil",
            "/secret/data/key",
        ] {
            assert_eq!(
                profile(vec![step("a", &[], WorkflowOperation::KvRead, target)]).validate(),
                Err(WorkflowError::InvalidTarget),
                "target {target} must be rejected"
            );
        }
    }

    #[test]
    fn payload_and_operation_digest_are_bounded_and_exact() {
        let profile = profile(vec![step(
            "a",
            &[],
            WorkflowOperation::KvWrite,
            "secret/data/key",
        )]);
        let mut values = BTreeMap::new();
        values.insert("a".into(), serde_json::json!({"data":{"value":"one"}}));
        let first = operation_digest("tenant", &profile, &values).unwrap();
        let second = operation_digest("tenant", &profile, &values).unwrap();
        assert_eq!(first, second);
        values.insert("a".into(), serde_json::json!({"data":{"value":"two"}}));
        assert_ne!(
            first,
            operation_digest("tenant", &profile, &values).unwrap()
        );
        values.insert(
            "a".into(),
            serde_json::json!("x".repeat(MAX_STEP_PAYLOAD_BYTES + 1)),
        );
        assert_eq!(
            validate_payloads(&values),
            Err(WorkflowError::PayloadTooLarge)
        );
    }

    #[test]
    fn restart_recovery_never_replays_an_active_step() {
        let binding = RunBinding::new([7; 32], "n", "p", 1, "r").unwrap();
        let mut run = WorkflowRun::new_with_operation("run", &binding, [9; 32]).unwrap();
        run.transition(RunPhase::Running).unwrap();
        run.active_step = Some("a".into());
        let mut state = WorkflowState {
            profiles: vec![],
            runs: vec![run],
        };
        assert!(state.recover_inflight());
        assert_eq!(state.runs[0].phase, RunPhase::ReconcileRequired);
        assert_eq!(state.runs[0].active_step.as_deref(), Some("a"));
    }
}
