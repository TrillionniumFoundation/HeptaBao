#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Fail-closed governance primitives for the HeptaBao H00 execution lane.
//!
//! This crate intentionally cannot grant production, compatibility, migration,
//! release or mixed-cluster authority.  It validates the minimum facts needed
//! for a qualification receipt and returns only [`AuthorityEffect::None`].

/// The only authority effect a qualification receipt may have.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityEffect {
    /// Qualification records evidence; it grants no operational authority.
    None,
}

/// Source, dependency, review and signature facts bound to one qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationFacts {
    pub clean_tree: bool,
    pub dependency_receipts_valid: bool,
    pub required_lanes_passed: bool,
    pub exit_gates_passed: bool,
    pub approvals_valid: bool,
    pub signature_valid: bool,
    pub current_and_unrevoked: bool,
}

/// Test counts carried by the candidate qualification receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestSummary {
    pub failed: u64,
    pub unknown: u64,
}

/// Open security and classification findings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingSummary {
    pub critical_open: u64,
    pub high_open: u64,
    pub unclassified: u64,
}

/// A bounded reason why qualification must fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationError {
    DirtySourceTree,
    InvalidDependencyReceipt,
    RequiredLaneNotPassed,
    FailedTest,
    UnknownTestOutcome,
    CriticalFinding,
    HighFinding,
    UnclassifiedFinding,
    ExitGateNotPassed,
    InvalidApprovalSet,
    InvalidSignature,
    ExpiredSupersededOrRevoked,
}

/// Validate the minimal qualification semantics.
///
/// Successful validation returns [`AuthorityEffect::None`].  A separate,
/// signed, scoped, expiring and revocable grant is required for any authority.
pub const fn qualify(
    facts: QualificationFacts,
    tests: TestSummary,
    findings: FindingSummary,
) -> Result<AuthorityEffect, QualificationError> {
    if !facts.clean_tree {
        return Err(QualificationError::DirtySourceTree);
    }
    if !facts.dependency_receipts_valid {
        return Err(QualificationError::InvalidDependencyReceipt);
    }
    if !facts.required_lanes_passed {
        return Err(QualificationError::RequiredLaneNotPassed);
    }
    if tests.failed != 0 {
        return Err(QualificationError::FailedTest);
    }
    if tests.unknown != 0 {
        return Err(QualificationError::UnknownTestOutcome);
    }
    if findings.critical_open != 0 {
        return Err(QualificationError::CriticalFinding);
    }
    if findings.high_open != 0 {
        return Err(QualificationError::HighFinding);
    }
    if findings.unclassified != 0 {
        return Err(QualificationError::UnclassifiedFinding);
    }
    if !facts.exit_gates_passed {
        return Err(QualificationError::ExitGateNotPassed);
    }
    if !facts.approvals_valid {
        return Err(QualificationError::InvalidApprovalSet);
    }
    if !facts.signature_valid {
        return Err(QualificationError::InvalidSignature);
    }
    if !facts.current_and_unrevoked {
        return Err(QualificationError::ExpiredSupersededOrRevoked);
    }
    Ok(AuthorityEffect::None)
}

/// Compile-time planning authority sentinels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanningAuthority {
    pub compatibility_claim: bool,
    pub production_authority: bool,
    pub migration_authority: bool,
    pub release_authority: bool,
    pub mixed_cluster_allowed: bool,
    pub openbao_physical_storage_read_allowed: bool,
    pub openbao_physical_storage_write_allowed: bool,
    pub real_secret_fixture_allowed: bool,
    pub root_token_fixture_allowed: bool,
    pub automatic_stage_promotion: bool,
}

/// H00 remains planning/implementation-only until separately signed grants exist.
pub const H00_AUTHORITY: PlanningAuthority = PlanningAuthority {
    compatibility_claim: false,
    production_authority: false,
    migration_authority: false,
    release_authority: false,
    mixed_cluster_allowed: false,
    openbao_physical_storage_read_allowed: false,
    openbao_physical_storage_write_allowed: false,
    real_secret_fixture_allowed: false,
    root_token_fixture_allowed: false,
    automatic_stage_promotion: false,
};

#[cfg(test)]
mod tests {
    use super::{
        AuthorityEffect, FindingSummary, H00_AUTHORITY, QualificationError, QualificationFacts,
        TestSummary, qualify,
    };

    const GOOD_FACTS: QualificationFacts = QualificationFacts {
        clean_tree: true,
        dependency_receipts_valid: true,
        required_lanes_passed: true,
        exit_gates_passed: true,
        approvals_valid: true,
        signature_valid: true,
        current_and_unrevoked: true,
    };

    const GOOD_TESTS: TestSummary = TestSummary {
        failed: 0,
        unknown: 0,
    };

    const GOOD_FINDINGS: FindingSummary = FindingSummary {
        critical_open: 0,
        high_open: 0,
        unclassified: 0,
    };

    #[test]
    fn qualification_never_grants_authority() {
        assert_eq!(
            qualify(GOOD_FACTS, GOOD_TESTS, GOOD_FINDINGS),
            Ok(AuthorityEffect::None)
        );
    }

    #[test]
    fn failed_tests_reject_qualification() {
        let tests = TestSummary {
            failed: 1,
            unknown: 0,
        };
        assert_eq!(
            qualify(GOOD_FACTS, tests, GOOD_FINDINGS),
            Err(QualificationError::FailedTest)
        );
    }

    #[test]
    fn unknown_tests_reject_qualification() {
        let tests = TestSummary {
            failed: 0,
            unknown: 1,
        };
        assert_eq!(
            qualify(GOOD_FACTS, tests, GOOD_FINDINGS),
            Err(QualificationError::UnknownTestOutcome)
        );
    }

    #[test]
    fn high_finding_rejects_qualification() {
        let findings = FindingSummary {
            critical_open: 0,
            high_open: 1,
            unclassified: 0,
        };
        assert_eq!(
            qualify(GOOD_FACTS, GOOD_TESTS, findings),
            Err(QualificationError::HighFinding)
        );
    }

    #[test]
    fn revoked_receipt_rejects_qualification() {
        let facts = QualificationFacts {
            current_and_unrevoked: false,
            ..GOOD_FACTS
        };
        assert_eq!(
            qualify(facts, GOOD_TESTS, GOOD_FINDINGS),
            Err(QualificationError::ExpiredSupersededOrRevoked)
        );
    }

    #[test]
    fn every_h00_authority_flag_is_false() {
        let authority = std::hint::black_box(H00_AUTHORITY);
        assert!(
            [
                authority.compatibility_claim,
                authority.production_authority,
                authority.migration_authority,
                authority.release_authority,
                authority.mixed_cluster_allowed,
                authority.openbao_physical_storage_read_allowed,
                authority.openbao_physical_storage_write_allowed,
                authority.real_secret_fixture_allowed,
                authority.root_token_fixture_allowed,
                authority.automatic_stage_promotion,
            ]
            .into_iter()
            .all(|flag| !flag)
        );
    }
}
