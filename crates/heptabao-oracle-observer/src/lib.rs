#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Secret-free, authority-free side-effect observation contracts for H01.
//!
//! This crate does not call OpenBao, create tokens, mutate a backend or grant
//! compatibility.  It validates metadata around a synthetic or black-box
//! capture and compares bounded counters/revisions before and after an
//! operation.  Raw secret material is intentionally unrepresentable.

/// Qualification and compatibility observations never grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityEffect {
    None,
}

/// Whether a record is a local synthetic contract test or a real black-box
/// observation produced inside the restricted Oracle lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureKind {
    SyntheticContract,
    BlackBoxOracle,
}

/// Metadata needed before a side-effect observation can be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationContext<'a> {
    pub baseline_id: &'a str,
    pub observation_id: &'a str,
    pub capture_kind: CaptureKind,
    pub artifact_signature_verified: bool,
    pub secret_material_present: bool,
    pub authority_effect: AuthorityEffect,
}

/// Fail-closed errors at the Oracle observation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationError {
    EmptyBaselineId,
    EmptyObservationId,
    UnverifiedOracleArtifact,
    SecretMaterialPresent,
    UnexpectedMountMutation,
    UnexpectedPolicyMutation,
    UnexpectedTokenMutation,
    UnexpectedLeaseMutation,
    UnexpectedAuditMutation,
    UnexpectedPluginMutation,
    UnexpectedRaftMutation,
    UnexpectedExternalEffectMutation,
    UnexpectedSealTransition,
    UnexpectedActiveTransition,
}

impl ObservationContext<'_> {
    /// Validate the metadata without creating any compatibility or execution
    /// authority.
    pub const fn validate(self) -> Result<AuthorityEffect, ObservationError> {
        if self.baseline_id.is_empty() {
            return Err(ObservationError::EmptyBaselineId);
        }
        if self.observation_id.is_empty() {
            return Err(ObservationError::EmptyObservationId);
        }
        if matches!(self.capture_kind, CaptureKind::BlackBoxOracle)
            && !self.artifact_signature_verified
        {
            return Err(ObservationError::UnverifiedOracleArtifact);
        }
        if self.secret_material_present {
            return Err(ObservationError::SecretMaterialPresent);
        }
        Ok(AuthorityEffect::None)
    }
}

/// Bounded, secret-free observable state captured around one operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SideEffectSnapshot {
    pub mount_revision: u64,
    pub policy_revision: u64,
    pub token_count: u64,
    pub lease_count: u64,
    pub audit_event_count: u64,
    pub plugin_process_count: u64,
    pub raft_commit_index: u64,
    pub external_effect_receipt_count: u64,
    pub sealed: bool,
    pub active: bool,
}

/// Signed differences between two bounded snapshots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SideEffectDelta {
    pub mount_revision: i128,
    pub policy_revision: i128,
    pub token_count: i128,
    pub lease_count: i128,
    pub audit_event_count: i128,
    pub plugin_process_count: i128,
    pub raft_commit_index: i128,
    pub external_effect_receipt_count: i128,
    pub sealed_changed: bool,
    pub active_changed: bool,
}

impl SideEffectDelta {
    pub const fn between(before: SideEffectSnapshot, after: SideEffectSnapshot) -> Self {
        Self {
            mount_revision: after.mount_revision as i128 - before.mount_revision as i128,
            policy_revision: after.policy_revision as i128 - before.policy_revision as i128,
            token_count: after.token_count as i128 - before.token_count as i128,
            lease_count: after.lease_count as i128 - before.lease_count as i128,
            audit_event_count: after.audit_event_count as i128 - before.audit_event_count as i128,
            plugin_process_count: after.plugin_process_count as i128
                - before.plugin_process_count as i128,
            raft_commit_index: after.raft_commit_index as i128 - before.raft_commit_index as i128,
            external_effect_receipt_count: after.external_effect_receipt_count as i128
                - before.external_effect_receipt_count as i128,
            sealed_changed: before.sealed != after.sealed,
            active_changed: before.active != after.active,
        }
    }

    pub const fn is_empty(self) -> bool {
        self.mount_revision == 0
            && self.policy_revision == 0
            && self.token_count == 0
            && self.lease_count == 0
            && self.audit_event_count == 0
            && self.plugin_process_count == 0
            && self.raft_commit_index == 0
            && self.external_effect_receipt_count == 0
            && !self.sealed_changed
            && !self.active_changed
    }
}

/// Explicit allowlist for the side effects a single observation may produce.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SideEffectPolicy {
    pub allow_mount_revision: bool,
    pub allow_policy_revision: bool,
    pub allow_token_count: bool,
    pub allow_lease_count: bool,
    pub allow_audit_event_count: bool,
    pub allow_plugin_process_count: bool,
    pub allow_raft_commit_index: bool,
    pub allow_external_effect_receipt_count: bool,
    pub allow_seal_transition: bool,
    pub allow_active_transition: bool,
}

/// Validate that every observed mutation was declared before capture.
pub const fn validate_delta(
    policy: SideEffectPolicy,
    delta: SideEffectDelta,
) -> Result<AuthorityEffect, ObservationError> {
    if delta.mount_revision != 0 && !policy.allow_mount_revision {
        return Err(ObservationError::UnexpectedMountMutation);
    }
    if delta.policy_revision != 0 && !policy.allow_policy_revision {
        return Err(ObservationError::UnexpectedPolicyMutation);
    }
    if delta.token_count != 0 && !policy.allow_token_count {
        return Err(ObservationError::UnexpectedTokenMutation);
    }
    if delta.lease_count != 0 && !policy.allow_lease_count {
        return Err(ObservationError::UnexpectedLeaseMutation);
    }
    if delta.audit_event_count != 0 && !policy.allow_audit_event_count {
        return Err(ObservationError::UnexpectedAuditMutation);
    }
    if delta.plugin_process_count != 0 && !policy.allow_plugin_process_count {
        return Err(ObservationError::UnexpectedPluginMutation);
    }
    if delta.raft_commit_index != 0 && !policy.allow_raft_commit_index {
        return Err(ObservationError::UnexpectedRaftMutation);
    }
    if delta.external_effect_receipt_count != 0 && !policy.allow_external_effect_receipt_count {
        return Err(ObservationError::UnexpectedExternalEffectMutation);
    }
    if delta.sealed_changed && !policy.allow_seal_transition {
        return Err(ObservationError::UnexpectedSealTransition);
    }
    if delta.active_changed && !policy.allow_active_transition {
        return Err(ObservationError::UnexpectedActiveTransition);
    }
    Ok(AuthorityEffect::None)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityEffect, CaptureKind, ObservationContext, ObservationError, SideEffectDelta,
        SideEffectPolicy, SideEffectSnapshot, validate_delta,
    };

    #[test]
    fn synthetic_contract_has_no_authority() {
        let context = ObservationContext {
            baseline_id: "HB-ORACLE-OPENBAO-V2_6_2",
            observation_id: "HB-SYNTHETIC-0001",
            capture_kind: CaptureKind::SyntheticContract,
            artifact_signature_verified: false,
            secret_material_present: false,
            authority_effect: AuthorityEffect::None,
        };
        assert_eq!(context.validate(), Ok(AuthorityEffect::None));
    }

    #[test]
    fn black_box_oracle_requires_verified_artifact() {
        let context = ObservationContext {
            baseline_id: "HB-ORACLE-OPENBAO-V2_6_2",
            observation_id: "HB-ORACLE-0001",
            capture_kind: CaptureKind::BlackBoxOracle,
            artifact_signature_verified: false,
            secret_material_present: false,
            authority_effect: AuthorityEffect::None,
        };
        assert_eq!(
            context.validate(),
            Err(ObservationError::UnverifiedOracleArtifact)
        );
    }

    #[test]
    fn secret_material_is_rejected() {
        let context = ObservationContext {
            baseline_id: "HB-ORACLE-OPENBAO-V2_6_2",
            observation_id: "HB-ORACLE-0002",
            capture_kind: CaptureKind::BlackBoxOracle,
            artifact_signature_verified: true,
            secret_material_present: true,
            authority_effect: AuthorityEffect::None,
        };
        assert_eq!(
            context.validate(),
            Err(ObservationError::SecretMaterialPresent)
        );
    }

    #[test]
    fn health_observation_allows_audit_only() {
        let before = SideEffectSnapshot {
            audit_event_count: 41,
            ..SideEffectSnapshot::default()
        };
        let after = SideEffectSnapshot {
            audit_event_count: 42,
            ..SideEffectSnapshot::default()
        };
        let delta = SideEffectDelta::between(before, after);
        let policy = SideEffectPolicy {
            allow_audit_event_count: true,
            ..SideEffectPolicy::default()
        };
        assert_eq!(validate_delta(policy, delta), Ok(AuthorityEffect::None));
    }

    #[test]
    fn undeclared_token_mutation_is_rejected() {
        let before = SideEffectSnapshot::default();
        let after = SideEffectSnapshot {
            token_count: 1,
            ..SideEffectSnapshot::default()
        };
        let delta = SideEffectDelta::between(before, after);
        assert_eq!(
            validate_delta(SideEffectPolicy::default(), delta),
            Err(ObservationError::UnexpectedTokenMutation)
        );
    }

    #[test]
    fn empty_delta_is_empty() {
        let snapshot = SideEffectSnapshot::default();
        assert!(SideEffectDelta::between(snapshot, snapshot).is_empty());
    }
}
