#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! H02 dependency bakeoff contracts.
//!
//! The crate scores and validates dependency candidates, but deliberately does
//! not select a runtime, TLS stack, cryptographic provider, storage client,
//! Raft library or plugin transport on its own.  A selection is only a scoped
//! engineering decision; it grants no compatibility or operational authority.

/// A platform capability that requires an explicit dependency decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    AsyncRuntime,
    HttpServer,
    HttpClient,
    Tls,
    CryptographicProvider,
    SecureMemory,
    Serialization,
    HclParsing,
    Postgres,
    Raft,
    Grpc,
    TemplateAndCel,
    Telemetry,
    Cli,
    LinuxSandbox,
    FuzzAndModelTooling,
}

/// Lifecycle state of a candidate in the H02 research lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateState {
    Identified,
    EvidenceCollecting,
    EligibleForBakeoff,
    Rejected,
    SelectedForPrototype,
}

/// Qualification and selection records never grant runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityEffect {
    None,
}

/// Scores are evidence summaries on a closed 0..=5 scale, where a higher
/// value always means a more favorable outcome after criterion-specific
/// normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScoreCard {
    pub maintenance: u8,
    pub security_history: u8,
    pub license_fit: u8,
    pub unsafe_surface: u8,
    pub api_stability: u8,
    pub rust_version_fit: u8,
    pub performance: u8,
    pub replacement_seam: u8,
    pub ecosystem_fit: u8,
    pub qualification_cost: u8,
}

impl ScoreCard {
    pub const MAX_SCORE: u16 = 50;

    pub const fn validate(self) -> Result<(), BakeoffError> {
        if self.maintenance > 5
            || self.security_history > 5
            || self.license_fit > 5
            || self.unsafe_surface > 5
            || self.api_stability > 5
            || self.rust_version_fit > 5
            || self.performance > 5
            || self.replacement_seam > 5
            || self.ecosystem_fit > 5
            || self.qualification_cost > 5
        {
            return Err(BakeoffError::ScoreOutOfRange);
        }
        Ok(())
    }

    pub const fn total(self) -> u16 {
        self.maintenance as u16
            + self.security_history as u16
            + self.license_fit as u16
            + self.unsafe_surface as u16
            + self.api_stability as u16
            + self.rust_version_fit as u16
            + self.performance as u16
            + self.replacement_seam as u16
            + self.ecosystem_fit as u16
            + self.qualification_cost as u16
    }
}

/// Evidence required before a candidate may be selected even for a prototype.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateEvidence {
    pub source_and_release_pinned: bool,
    pub license_reviewed: bool,
    pub maintenance_reviewed: bool,
    pub security_advisories_reviewed: bool,
    pub unsafe_inventory_reviewed: bool,
    pub minimum_rust_version_verified: bool,
    pub api_and_replacement_seam_reviewed: bool,
    pub deterministic_tests_available: bool,
    pub benchmark_profile_available: bool,
    pub qualification_plan_available: bool,
    pub critical_findings_open: u32,
    pub high_findings_open: u32,
    pub unclassified_findings: u32,
}

/// Candidate identity and its reviewed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate<'a> {
    pub candidate_id: &'a str,
    pub package_or_project: &'a str,
    pub capability: Capability,
    pub state: CandidateState,
    pub score: ScoreCard,
    pub evidence: CandidateEvidence,
}

/// Result of a prototype selection decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrototypeSelection<'a> {
    pub candidate_id: &'a str,
    pub capability: Capability,
    pub score: u16,
    pub authority_effect: AuthorityEffect,
}

/// Why a dependency candidate must fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BakeoffError {
    EmptyCandidateId,
    EmptyProjectName,
    ScoreOutOfRange,
    CandidateRejected,
    CandidateNotEligible,
    SourceOrReleaseNotPinned,
    LicenseReviewMissing,
    MaintenanceReviewMissing,
    AdvisoryReviewMissing,
    UnsafeInventoryMissing,
    RustVersionEvidenceMissing,
    ReplacementSeamMissing,
    DeterministicTestsMissing,
    BenchmarkMissing,
    QualificationPlanMissing,
    CriticalFindingOpen,
    HighFindingOpen,
    UnclassifiedFinding,
    MinimumScoreNotMet,
}

/// Minimum normalized score for prototype selection.  Meeting it is necessary
/// but never sufficient; every critical evidence flag must also pass.
pub const PROTOTYPE_SELECTION_MINIMUM: u16 = 38;

/// Validate a candidate without changing its state.
pub const fn validate_candidate(candidate: Candidate<'_>) -> Result<AuthorityEffect, BakeoffError> {
    if candidate.candidate_id.is_empty() {
        return Err(BakeoffError::EmptyCandidateId);
    }
    if candidate.package_or_project.is_empty() {
        return Err(BakeoffError::EmptyProjectName);
    }
    match candidate.score.validate() {
        Ok(()) => {}
        Err(error) => return Err(error),
    }
    if matches!(candidate.state, CandidateState::Rejected) {
        return Err(BakeoffError::CandidateRejected);
    }
    Ok(AuthorityEffect::None)
}

/// Select a candidate for a bounded prototype only after all fail-closed H02
/// evidence has passed.  Production use requires later Program Gate receipts
/// and a separate authority grant.
pub const fn select_for_prototype(
    candidate: Candidate<'_>,
) -> Result<PrototypeSelection<'_>, BakeoffError> {
    match validate_candidate(candidate) {
        Ok(AuthorityEffect::None) => {}
        Err(error) => return Err(error),
    }
    if !matches!(candidate.state, CandidateState::EligibleForBakeoff) {
        return Err(BakeoffError::CandidateNotEligible);
    }
    let evidence = candidate.evidence;
    if !evidence.source_and_release_pinned {
        return Err(BakeoffError::SourceOrReleaseNotPinned);
    }
    if !evidence.license_reviewed {
        return Err(BakeoffError::LicenseReviewMissing);
    }
    if !evidence.maintenance_reviewed {
        return Err(BakeoffError::MaintenanceReviewMissing);
    }
    if !evidence.security_advisories_reviewed {
        return Err(BakeoffError::AdvisoryReviewMissing);
    }
    if !evidence.unsafe_inventory_reviewed {
        return Err(BakeoffError::UnsafeInventoryMissing);
    }
    if !evidence.minimum_rust_version_verified {
        return Err(BakeoffError::RustVersionEvidenceMissing);
    }
    if !evidence.api_and_replacement_seam_reviewed {
        return Err(BakeoffError::ReplacementSeamMissing);
    }
    if !evidence.deterministic_tests_available {
        return Err(BakeoffError::DeterministicTestsMissing);
    }
    if !evidence.benchmark_profile_available {
        return Err(BakeoffError::BenchmarkMissing);
    }
    if !evidence.qualification_plan_available {
        return Err(BakeoffError::QualificationPlanMissing);
    }
    if evidence.critical_findings_open != 0 {
        return Err(BakeoffError::CriticalFindingOpen);
    }
    if evidence.high_findings_open != 0 {
        return Err(BakeoffError::HighFindingOpen);
    }
    if evidence.unclassified_findings != 0 {
        return Err(BakeoffError::UnclassifiedFinding);
    }
    let total = candidate.score.total();
    if total < PROTOTYPE_SELECTION_MINIMUM {
        return Err(BakeoffError::MinimumScoreNotMet);
    }
    Ok(PrototypeSelection {
        candidate_id: candidate.candidate_id,
        capability: candidate.capability,
        score: total,
        authority_effect: AuthorityEffect::None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityEffect, BakeoffError, Candidate, CandidateEvidence, CandidateState, Capability,
        PROTOTYPE_SELECTION_MINIMUM, ScoreCard, select_for_prototype, validate_candidate,
    };

    const GOOD_SCORE: ScoreCard = ScoreCard {
        maintenance: 4,
        security_history: 4,
        license_fit: 5,
        unsafe_surface: 4,
        api_stability: 4,
        rust_version_fit: 5,
        performance: 4,
        replacement_seam: 4,
        ecosystem_fit: 4,
        qualification_cost: 4,
    };

    const GOOD_EVIDENCE: CandidateEvidence = CandidateEvidence {
        source_and_release_pinned: true,
        license_reviewed: true,
        maintenance_reviewed: true,
        security_advisories_reviewed: true,
        unsafe_inventory_reviewed: true,
        minimum_rust_version_verified: true,
        api_and_replacement_seam_reviewed: true,
        deterministic_tests_available: true,
        benchmark_profile_available: true,
        qualification_plan_available: true,
        critical_findings_open: 0,
        high_findings_open: 0,
        unclassified_findings: 0,
    };

    const GOOD_CANDIDATE: Candidate<'static> = Candidate {
        candidate_id: "HB-DEP-RUNTIME-SYNTHETIC-A",
        package_or_project: "synthetic-runtime-a",
        capability: Capability::AsyncRuntime,
        state: CandidateState::EligibleForBakeoff,
        score: GOOD_SCORE,
        evidence: GOOD_EVIDENCE,
    };

    #[test]
    fn validated_candidate_has_no_authority() {
        assert_eq!(
            validate_candidate(GOOD_CANDIDATE),
            Ok(AuthorityEffect::None)
        );
    }

    #[test]
    fn complete_candidate_can_be_selected_for_prototype_only() {
        let selection = select_for_prototype(GOOD_CANDIDATE);
        assert_eq!(
            selection,
            Ok(super::PrototypeSelection {
                candidate_id: "HB-DEP-RUNTIME-SYNTHETIC-A",
                capability: Capability::AsyncRuntime,
                score: GOOD_SCORE.total(),
                authority_effect: AuthorityEffect::None,
            })
        );
        assert!(GOOD_SCORE.total() >= PROTOTYPE_SELECTION_MINIMUM);
    }

    #[test]
    fn pending_license_rejects_selection() {
        let candidate = Candidate {
            evidence: CandidateEvidence {
                license_reviewed: false,
                ..GOOD_EVIDENCE
            },
            ..GOOD_CANDIDATE
        };
        assert_eq!(
            select_for_prototype(candidate),
            Err(BakeoffError::LicenseReviewMissing)
        );
    }

    #[test]
    fn unclassified_finding_rejects_selection() {
        let candidate = Candidate {
            evidence: CandidateEvidence {
                unclassified_findings: 1,
                ..GOOD_EVIDENCE
            },
            ..GOOD_CANDIDATE
        };
        assert_eq!(
            select_for_prototype(candidate),
            Err(BakeoffError::UnclassifiedFinding)
        );
    }

    #[test]
    fn identified_candidate_is_not_selectable() {
        let candidate = Candidate {
            state: CandidateState::Identified,
            ..GOOD_CANDIDATE
        };
        assert_eq!(
            select_for_prototype(candidate),
            Err(BakeoffError::CandidateNotEligible)
        );
    }

    #[test]
    fn low_score_is_not_selectable() {
        let candidate = Candidate {
            score: ScoreCard {
                maintenance: 3,
                security_history: 3,
                license_fit: 3,
                unsafe_surface: 3,
                api_stability: 3,
                rust_version_fit: 3,
                performance: 3,
                replacement_seam: 3,
                ecosystem_fit: 3,
                qualification_cost: 3,
            },
            ..GOOD_CANDIDATE
        };
        assert_eq!(
            select_for_prototype(candidate),
            Err(BakeoffError::MinimumScoreNotMet)
        );
    }
}
