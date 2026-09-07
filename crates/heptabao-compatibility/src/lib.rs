#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Differential compatibility evidence and fail-closed claim admission.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use heptabao_domain::Id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    RepositoryControlled,
    Independent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationResult {
    Match,
    ResponseMismatch,
    SideEffectMismatch,
    MissingActual,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Observation {
    pub operation_id: Id,
    pub expected_response_digest: [u8; 32],
    pub actual_response_digest: Option<[u8; 32]>,
    pub expected_side_effect_digest: [u8; 32],
    pub actual_side_effect_digest: Option<[u8; 32]>,
}

impl Observation {
    pub fn result(&self) -> ObservationResult {
        let Some(actual_response) = self.actual_response_digest else {
            return ObservationResult::MissingActual;
        };
        let Some(actual_side_effect) = self.actual_side_effect_digest else {
            return ObservationResult::MissingActual;
        };
        if actual_response != self.expected_response_digest {
            return ObservationResult::ResponseMismatch;
        }
        if actual_side_effect != self.expected_side_effect_digest {
            return ObservationResult::SideEffectMismatch;
        }
        ObservationResult::Match
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimStatus {
    Candidate,
    Admitted,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityClaim {
    pub profile_id: Id,
    pub status: ClaimStatus,
    pub observation_count: usize,
    pub evidence_origin: EvidenceOrigin,
}

#[derive(Debug)]
pub struct CompatibilityMatrix {
    profile_id: Id,
    observations: BTreeMap<Id, Observation>,
}

impl CompatibilityMatrix {
    pub fn new(profile_id: Id) -> Self {
        Self {
            profile_id,
            observations: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, observation: Observation) -> Result<(), CompatibilityError> {
        if self.observations.contains_key(&observation.operation_id) {
            return Err(CompatibilityError::DuplicateObservation);
        }
        self.observations
            .insert(observation.operation_id.clone(), observation);
        Ok(())
    }

    pub fn mismatches(&self) -> Vec<Id> {
        self.observations
            .values()
            .filter(|observation| observation.result() != ObservationResult::Match)
            .map(|observation| observation.operation_id.clone())
            .collect()
    }

    pub fn admit(
        &self,
        evidence_origin: EvidenceOrigin,
    ) -> Result<CompatibilityClaim, CompatibilityError> {
        if evidence_origin != EvidenceOrigin::Independent {
            return Err(CompatibilityError::IndependentEvidenceRequired);
        }
        if self.observations.is_empty() {
            return Err(CompatibilityError::EmptyMatrix);
        }
        if !self.mismatches().is_empty() {
            return Err(CompatibilityError::MatrixMismatch);
        }
        Ok(CompatibilityClaim {
            profile_id: self.profile_id.clone(),
            status: ClaimStatus::Admitted,
            observation_count: self.observations.len(),
            evidence_origin,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    DuplicateObservation,
    EmptyMatrix,
    MatrixMismatch,
    IndependentEvidenceRequired,
}

impl fmt::Display for CompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicateObservation => "compatibility observation already exists",
            Self::EmptyMatrix => "compatibility matrix is empty",
            Self::MatrixMismatch => "compatibility matrix contains a mismatch",
            Self::IndependentEvidenceRequired => "independent evidence is required",
        })
    }
}

impl Error for CompatibilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn matching_observation() -> Result<Observation, Box<dyn Error>> {
        Ok(Observation {
            operation_id: Id::parse("kv_read")?,
            expected_response_digest: [1; 32],
            actual_response_digest: Some([1; 32]),
            expected_side_effect_digest: [2; 32],
            actual_side_effect_digest: Some([2; 32]),
        })
    }

    #[test]
    fn repository_cannot_self_admit_compatibility() -> Result<(), Box<dyn Error>> {
        let mut matrix = CompatibilityMatrix::new(Id::parse("openbao_v2_6")?);
        matrix.add(matching_observation()?)?;
        assert_eq!(
            Err(CompatibilityError::IndependentEvidenceRequired),
            matrix.admit(EvidenceOrigin::RepositoryControlled)
        );
        assert!(matrix.admit(EvidenceOrigin::Independent).is_ok());
        Ok(())
    }

    #[test]
    fn side_effect_mismatch_blocks_admission() -> Result<(), Box<dyn Error>> {
        let mut observation = matching_observation()?;
        observation.actual_side_effect_digest = Some([3; 32]);
        let mut matrix = CompatibilityMatrix::new(Id::parse("openbao_v2_6")?);
        matrix.add(observation)?;
        assert_eq!(
            Err(CompatibilityError::MatrixMismatch),
            matrix.admit(EvidenceOrigin::Independent)
        );
        Ok(())
    }
}
