#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Differential compatibility evidence with an exact, fail-closed denominator.
//!
//! A compatibility claim binds an immutable surface inventory, an independently
//! produced Oracle/candidate artifact pair and at least the declared number of
//! matching observations for every required surface. Repository-controlled or
//! partial evidence can be inspected but can never be admitted.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;

use heptabao_domain::Id;

const MAX_SURFACE_ID_BYTES: usize = 96;
const MAX_SURFACES: usize = 1024;
const MAX_OBSERVATIONS: usize = 65_536;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SurfaceId(String);

impl SurfaceId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CompatibilityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SURFACE_ID_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || !value.bytes().all(|byte| {
                byte.is_ascii_uppercase()
                    || byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_')
            })
        {
            return Err(CompatibilityError::InvalidSurfaceId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SurfaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SurfaceId").field(&self.0).finish()
    }
}

impl fmt::Display for SurfaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    RepositoryControlled,
    Independent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceBinding {
    pub origin: EvidenceOrigin,
    pub inventory_sha256: [u8; 32],
    pub oracle_artifact_sha256: [u8; 32],
    pub candidate_artifact_sha256: [u8; 32],
}

impl EvidenceBinding {
    pub fn validate(self) -> Result<Self, CompatibilityError> {
        if self.inventory_sha256 == [0; 32]
            || self.oracle_artifact_sha256 == [0; 32]
            || self.candidate_artifact_sha256 == [0; 32]
            || self.oracle_artifact_sha256 == self.candidate_artifact_sha256
        {
            return Err(CompatibilityError::InvalidEvidenceBinding);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceRequirement {
    pub surface_id: SurfaceId,
    pub minimum_observations: NonZeroU16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceCatalog {
    profile_id: Id,
    inventory_sha256: [u8; 32],
    requirements: BTreeMap<SurfaceId, SurfaceRequirement>,
}

impl SurfaceCatalog {
    pub fn new(
        profile_id: Id,
        inventory_sha256: [u8; 32],
        requirements: impl IntoIterator<Item = SurfaceRequirement>,
    ) -> Result<Self, CompatibilityError> {
        if inventory_sha256 == [0; 32] {
            return Err(CompatibilityError::InvalidEvidenceBinding);
        }
        let mut by_id = BTreeMap::new();
        for requirement in requirements {
            if by_id
                .insert(requirement.surface_id.clone(), requirement)
                .is_some()
            {
                return Err(CompatibilityError::DuplicateSurface);
            }
            if by_id.len() > MAX_SURFACES {
                return Err(CompatibilityError::CatalogTooLarge);
            }
        }
        if by_id.is_empty() {
            return Err(CompatibilityError::EmptyCatalog);
        }
        Ok(Self {
            profile_id,
            inventory_sha256,
            requirements: by_id,
        })
    }

    pub fn profile_id(&self) -> &Id {
        &self.profile_id
    }

    pub const fn inventory_sha256(&self) -> [u8; 32] {
        self.inventory_sha256
    }

    pub fn requirements(&self) -> impl Iterator<Item = &SurfaceRequirement> {
        self.requirements.values()
    }

    pub fn len(&self) -> usize {
        self.requirements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }
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
    pub surface_id: SurfaceId,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageReport {
    pub required_surfaces: usize,
    pub observed_surfaces: usize,
    pub matching_observations: usize,
    pub total_observations: usize,
    pub missing_surfaces: Vec<SurfaceId>,
    pub mismatched_operations: Vec<Id>,
}

impl CoverageReport {
    pub fn complete(&self) -> bool {
        self.required_surfaces == self.observed_surfaces
            && self.missing_surfaces.is_empty()
            && self.mismatched_operations.is_empty()
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
    pub surface_count: usize,
    pub observation_count: usize,
    pub evidence: EvidenceBinding,
}

#[derive(Debug)]
pub struct CompatibilityMatrix {
    catalog: SurfaceCatalog,
    observations: BTreeMap<Id, Observation>,
}

impl CompatibilityMatrix {
    pub fn new(catalog: SurfaceCatalog) -> Self {
        Self {
            catalog,
            observations: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, observation: Observation) -> Result<(), CompatibilityError> {
        if !self
            .catalog
            .requirements
            .contains_key(&observation.surface_id)
        {
            return Err(CompatibilityError::UnknownSurface);
        }
        if self.observations.contains_key(&observation.operation_id) {
            return Err(CompatibilityError::DuplicateObservation);
        }
        if self.observations.len() >= MAX_OBSERVATIONS {
            return Err(CompatibilityError::ObservationCapacityExceeded);
        }
        self.observations
            .insert(observation.operation_id.clone(), observation);
        Ok(())
    }

    pub fn coverage(&self) -> CoverageReport {
        let mut counts = BTreeMap::<SurfaceId, usize>::new();
        let mut mismatched_operations = Vec::new();
        let mut matching_observations = 0;
        for observation in self.observations.values() {
            *counts.entry(observation.surface_id.clone()).or_default() += 1;
            if observation.result() == ObservationResult::Match {
                matching_observations += 1;
            } else {
                mismatched_operations.push(observation.operation_id.clone());
            }
        }
        let missing_surfaces = self
            .catalog
            .requirements()
            .filter(|requirement| {
                counts
                    .get(&requirement.surface_id)
                    .copied()
                    .unwrap_or_default()
                    < usize::from(requirement.minimum_observations.get())
            })
            .map(|requirement| requirement.surface_id.clone())
            .collect::<Vec<_>>();
        let observed_surfaces = self
            .catalog
            .requirements()
            .filter(|requirement| !missing_surfaces.contains(&requirement.surface_id))
            .count();
        CoverageReport {
            required_surfaces: self.catalog.len(),
            observed_surfaces,
            matching_observations,
            total_observations: self.observations.len(),
            missing_surfaces,
            mismatched_operations,
        }
    }

    pub fn admit(
        &self,
        evidence: EvidenceBinding,
    ) -> Result<CompatibilityClaim, CompatibilityError> {
        let evidence = evidence.validate()?;
        if evidence.origin != EvidenceOrigin::Independent {
            return Err(CompatibilityError::IndependentEvidenceRequired);
        }
        if evidence.inventory_sha256 != self.catalog.inventory_sha256() {
            return Err(CompatibilityError::InventoryBindingMismatch);
        }
        let coverage = self.coverage();
        if !coverage.mismatched_operations.is_empty() {
            return Err(CompatibilityError::MatrixMismatch);
        }
        if !coverage.complete() {
            return Err(CompatibilityError::IncompleteCoverage);
        }
        Ok(CompatibilityClaim {
            profile_id: self.catalog.profile_id().clone(),
            status: ClaimStatus::Admitted,
            surface_count: coverage.required_surfaces,
            observation_count: coverage.total_observations,
            evidence,
        })
    }

    pub fn observed_surface_ids(&self) -> BTreeSet<SurfaceId> {
        self.observations
            .values()
            .map(|observation| observation.surface_id.clone())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityError {
    InvalidSurfaceId,
    DuplicateSurface,
    EmptyCatalog,
    CatalogTooLarge,
    UnknownSurface,
    DuplicateObservation,
    ObservationCapacityExceeded,
    MatrixMismatch,
    IncompleteCoverage,
    IndependentEvidenceRequired,
    InvalidEvidenceBinding,
    InventoryBindingMismatch,
}

impl fmt::Display for CompatibilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSurfaceId => "compatibility surface identifier is invalid",
            Self::DuplicateSurface => "compatibility surface is duplicated",
            Self::EmptyCatalog => "compatibility surface catalog is empty",
            Self::CatalogTooLarge => "compatibility surface catalog exceeds its bound",
            Self::UnknownSurface => "observation references an undeclared surface",
            Self::DuplicateObservation => "compatibility observation already exists",
            Self::ObservationCapacityExceeded => "compatibility observation capacity is exhausted",
            Self::MatrixMismatch => "compatibility matrix contains a mismatch",
            Self::IncompleteCoverage => "compatibility matrix does not cover the exact denominator",
            Self::IndependentEvidenceRequired => "independent evidence is required",
            Self::InvalidEvidenceBinding => "compatibility evidence binding is invalid",
            Self::InventoryBindingMismatch => {
                "compatibility evidence is bound to another inventory"
            }
        })
    }
}

impl Error for CompatibilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Result<SurfaceCatalog, Box<dyn Error>> {
        Ok(SurfaceCatalog::new(
            Id::parse("openbao_v2_6_2")?,
            [9; 32],
            [
                SurfaceRequirement {
                    surface_id: SurfaceId::parse("HB-SURFACE-SECRET-KV")?,
                    minimum_observations: NonZeroU16::new(2)
                        .ok_or(CompatibilityError::EmptyCatalog)?,
                },
                SurfaceRequirement {
                    surface_id: SurfaceId::parse("HB-SURFACE-AUTH-TOKEN")?,
                    minimum_observations: NonZeroU16::new(1)
                        .ok_or(CompatibilityError::EmptyCatalog)?,
                },
            ],
        )?)
    }

    fn matching_observation(surface: &str, operation: &str) -> Result<Observation, Box<dyn Error>> {
        Ok(Observation {
            surface_id: SurfaceId::parse(surface)?,
            operation_id: Id::parse(operation)?,
            expected_response_digest: [1; 32],
            actual_response_digest: Some([1; 32]),
            expected_side_effect_digest: [2; 32],
            actual_side_effect_digest: Some([2; 32]),
        })
    }

    fn independent_binding() -> EvidenceBinding {
        EvidenceBinding {
            origin: EvidenceOrigin::Independent,
            inventory_sha256: [9; 32],
            oracle_artifact_sha256: [7; 32],
            candidate_artifact_sha256: [8; 32],
        }
    }

    #[test]
    fn repository_cannot_self_admit_compatibility() -> Result<(), Box<dyn Error>> {
        let mut matrix = CompatibilityMatrix::new(catalog()?);
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_read")?)?;
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_write")?)?;
        matrix.add(matching_observation(
            "HB-SURFACE-AUTH-TOKEN",
            "token_lookup",
        )?)?;
        let mut binding = independent_binding();
        binding.origin = EvidenceOrigin::RepositoryControlled;
        assert_eq!(
            Err(CompatibilityError::IndependentEvidenceRequired),
            matrix.admit(binding)
        );
        Ok(())
    }

    #[test]
    fn exact_denominator_and_minimum_count_are_mandatory() -> Result<(), Box<dyn Error>> {
        let mut matrix = CompatibilityMatrix::new(catalog()?);
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_read")?)?;
        matrix.add(matching_observation(
            "HB-SURFACE-AUTH-TOKEN",
            "token_lookup",
        )?)?;
        let coverage = matrix.coverage();
        assert_eq!(2, coverage.required_surfaces);
        assert_eq!(1, coverage.observed_surfaces);
        assert_eq!(
            Err(CompatibilityError::IncompleteCoverage),
            matrix.admit(independent_binding())
        );
        Ok(())
    }

    #[test]
    fn complete_independent_matrix_is_exactly_bound_and_admitted() -> Result<(), Box<dyn Error>> {
        let mut matrix = CompatibilityMatrix::new(catalog()?);
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_read")?)?;
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_write")?)?;
        matrix.add(matching_observation(
            "HB-SURFACE-AUTH-TOKEN",
            "token_lookup",
        )?)?;
        let claim = matrix.admit(independent_binding())?;
        assert_eq!(ClaimStatus::Admitted, claim.status);
        assert_eq!(2, claim.surface_count);
        assert_eq!(3, claim.observation_count);
        Ok(())
    }

    #[test]
    fn side_effect_mismatch_blocks_admission() -> Result<(), Box<dyn Error>> {
        let mut observation = matching_observation("HB-SURFACE-SECRET-KV", "kv_read")?;
        observation.actual_side_effect_digest = Some([3; 32]);
        let mut matrix = CompatibilityMatrix::new(catalog()?);
        matrix.add(observation)?;
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_write")?)?;
        matrix.add(matching_observation(
            "HB-SURFACE-AUTH-TOKEN",
            "token_lookup",
        )?)?;
        assert_eq!(
            Err(CompatibilityError::MatrixMismatch),
            matrix.admit(independent_binding())
        );
        Ok(())
    }

    #[test]
    fn unknown_surface_and_inventory_rebinding_fail_closed() -> Result<(), Box<dyn Error>> {
        let mut matrix = CompatibilityMatrix::new(catalog()?);
        assert_eq!(
            Err(CompatibilityError::UnknownSurface),
            matrix.add(matching_observation("HB-SURFACE-SECRET-PKI", "pki_issue")?)
        );
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_read")?)?;
        matrix.add(matching_observation("HB-SURFACE-SECRET-KV", "kv_write")?)?;
        matrix.add(matching_observation(
            "HB-SURFACE-AUTH-TOKEN",
            "token_lookup",
        )?)?;
        let mut rebound = independent_binding();
        rebound.inventory_sha256 = [6; 32];
        assert_eq!(
            Err(CompatibilityError::InventoryBindingMismatch),
            matrix.admit(rebound)
        );
        Ok(())
    }
}
