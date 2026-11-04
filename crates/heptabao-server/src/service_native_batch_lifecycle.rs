//! Affine metadata custody for an actual typed native batch finalizer. The domain
//! still authenticates and seals once. This owner cannot mint a credential,
//! acquire a new clock/proof, or authorize an issuer without its independent owner.
use super::*;
use crate::auth::batch_namespace::Registry;

fn metadata_digest<T: serde::Serialize>(value: &T) -> Result<[u8; 32], Response> {
    let bytes = owner_store::serialize_owner(value).map_err(|_| rejected())?;
    Ok(crypto::digest(&bytes))
}

pub(super) struct NativeBatchLifecycleOwner {
    cluster_id: String,
    deadline: OriginalDeadline,
    source_root: [u8; 32],
    source_catalog: [u8; 32],
    source_registry: Option<Registry>,
    expected_catalog: [u8; 32],
    expected_registry: Registry,
    admitted_batch: Option<bool>,
    admitted_catalog: Option<[u8; 32]>,
    admitted_auth: Option<[u8; 32]>,
    planned: bool,
}

impl NativeBatchLifecycleOwner {
    pub(super) fn prepare(
        source: &State,
        root: &RecordStateRootV6,
        deadline: OriginalDeadline,
    ) -> Result<Self, Response> {
        deadline.check().map_err(|_| rejected())?;
        namespaces::native_empty::empty_profile(source)?;
        source.validate_format()?;
        if source.cluster_id != root.cluster_id || source.schema != root.state_schema {
            return Err(rejected());
        }
        // Derive the exact deterministic catalog from the original complete
        // metadata. This throw-away candidate grants neither a token nor a
        // publication: only the actual domain finalizer may select it below.
        let mut expected = source.clone();
        expected.ensure_namespace_batch_registry()?;
        namespaces::native_empty::empty_profile(&expected)?;
        expected.validate_format()?;
        let expected_registry = expected
            .auth
            .namespace_batch_registry()
            .cloned()
            .ok_or_else(rejected)?;
        let owner = Self {
            cluster_id: source.cluster_id.clone(),
            deadline,
            source_root: crypto::digest(&root.encode().map_err(|_| rejected())?),
            source_catalog: metadata_digest(&source.namespaces)?,
            source_registry: source.auth.namespace_batch_registry().cloned(),
            expected_catalog: metadata_digest(&expected.namespaces)?,
            expected_registry,
            admitted_batch: None,
            admitted_catalog: None,
            admitted_auth: None,
            planned: false,
        };
        owner.check_source(source, root)?;
        Ok(owner)
    }

    fn check_source(&self, source: &State, root: &RecordStateRootV6) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        namespaces::native_empty::empty_profile(source)?;
        source.validate_format()?;
        if source.cluster_id != self.cluster_id
            || source.cluster_id != root.cluster_id
            || source.schema != root.state_schema
            || crypto::digest(&root.encode().map_err(|_| rejected())?) != self.source_root
            || metadata_digest(&source.namespaces)? != self.source_catalog
            || source.auth.namespace_batch_registry() != self.source_registry.as_ref()
        {
            return Err(rejected());
        }
        self.deadline.check().map_err(|_| rejected())
    }

    /// The caller first verifies the real opaque credential using the actual
    /// typed issuer owner and original request time. An error or service-token
    /// response must leave the complete Namespace owner exactly unchanged.
    pub(super) fn admit_domain_candidate(
        &mut self,
        source: &State,
        prior: &RecordStateRootV6,
        candidate: &State,
        is_batch: bool,
    ) -> Result<(), Response> {
        if self.admitted_batch.is_some() || self.planned {
            return Err(rejected());
        }
        self.check_source(source, prior)?;
        namespaces::native_empty::empty_profile(candidate)?;
        candidate.validate_namespace_batch_state()?;
        candidate
            .auth
            .validate_namespace_batch_successor(&source.auth)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let catalog = metadata_digest(&candidate.namespaces)?;
        let (expected_catalog, expected_registry) = if is_batch {
            (self.expected_catalog, Some(&self.expected_registry))
        } else {
            (self.source_catalog, self.source_registry.as_ref())
        };
        if candidate.cluster_id != self.cluster_id
            || candidate.replay_epoch != source.replay_epoch
            || candidate.global_lossless_json_format != source.global_lossless_json_format
            || catalog != expected_catalog
            || candidate.auth.namespace_batch_registry() != expected_registry
        {
            return Err(rejected());
        }
        self.admitted_auth = Some(metadata_digest(&candidate.auth)?);
        self.admitted_catalog = Some(catalog);
        self.admitted_batch = Some(is_batch);
        self.deadline.check().map_err(|_| rejected())
    }

    /// Check the planner's actual materialized candidate, not just a domain
    /// allow-list. The only extra root delta is the exact Namespace ledger
    /// derived above, together with the original Auth/Identity transaction.
    pub(super) fn admit_plan(
        &mut self,
        source: &State,
        prior: &RecordStateRootV6,
        candidate: &State,
        next: &RecordStateRootV6,
    ) -> Result<(), Response> {
        if self.planned {
            return Err(rejected());
        }
        self.check_source(source, prior)?;
        let batch = self.admitted_batch.ok_or_else(rejected)?;
        if self.admitted_catalog != Some(metadata_digest(&candidate.namespaces)?)
            || self.admitted_auth != Some(metadata_digest(&candidate.auth)?)
        {
            return Err(rejected());
        }
        namespaces::native_empty::empty_profile(candidate)?;
        candidate.validate_format()?;
        let mut normalized = next.clone();
        if batch {
            let old = prior
                .owners
                .iter()
                .find(|owner| owner.domain == OwnerDomain::Namespaces)
                .ok_or_else(rejected)?;
            let new = normalized
                .owners
                .iter_mut()
                .find(|owner| owner.domain == OwnerDomain::Namespaces)
                .ok_or_else(rejected)?;
            *new = old.clone();
        }
        auth_only_root_change(prior, &normalized, true)?;
        self.planned = true;
        self.deadline.check().map_err(|_| rejected())
    }

    pub(super) fn check_installed(&self, state: &State) -> Result<(), Response> {
        self.deadline.check().map_err(|_| rejected())?;
        if !self.planned
            || self.admitted_batch.is_none()
            || state.cluster_id != self.cluster_id
            || self.admitted_catalog != Some(metadata_digest(&state.namespaces)?)
        {
            return Err(rejected());
        }
        let registry = if self.admitted_batch == Some(true) {
            Some(&self.expected_registry)
        } else {
            self.source_registry.as_ref()
        };
        if state.auth.namespace_batch_registry() != registry {
            return Err(rejected());
        }
        // The original terminal clock owner may update Auth. Its exact final
        // checkpoint and NativeProof remain mandatory in NativeAuthDelivery;
        // this check retains the immutable Namespace and matching ledger.
        state.validate_namespace_batch_state()?;
        namespaces::native_empty::empty_profile(state)?;
        self.deadline.check().map_err(|_| rejected())
    }
}
