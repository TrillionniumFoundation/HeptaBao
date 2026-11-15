//! Exact Auth removal paired with one successful, owned mount disable.
//! This value grants neither an engine operation nor a publication. The real
//! engine owner consumes it only for its own disabled namespace/mount, while
//! retaining its original complete-root and terminal-delivery constraints.
use super::*;
use crate::state_record_root::{OpaqueOwnerRef, StateIdentity};
use crate::state_record_root_v6::{OwnerDomain, RecordStateRootV6};
use crate::v6_native_custody::OriginalDeadline;

fn unavailable() -> AuthError {
    AuthError {
        status: 503,
        message: "quota mount retirement custody changed".into(),
    }
}

fn auth_owner(root: &RecordStateRootV6) -> Result<&OpaqueOwnerRef, AuthError> {
    root.owners
        .iter()
        .find(|owner| owner.domain == OwnerDomain::Auth)
        .map(|owner| &owner.owner)
        .ok_or_else(unavailable)
}

fn canonical(auth: &AuthState) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    crate::secret_serde::to_vec(auth, crate::MAX_APPLICATION_STATE_BYTES).map_err(|_| unavailable())
}

/// Private, affine and non-serialized. Both Auth descriptors are checked
/// against the actual canonical source/candidate before any normalization.
/// The complete source and target identities bind the surrounding root too.
pub(crate) struct MountRetirement {
    namespace: String,
    mount: String,
    source_identity: StateIdentity,
    target_identity: StateIdentity,
    source_auth: OpaqueOwnerRef,
    target_auth: OpaqueOwnerRef,
    source_auth_digest: [u8; 32],
    target_auth_digest: [u8; 32],
    deadline: OriginalDeadline,
}

impl MountRetirement {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        source: &AuthState,
        candidate: &AuthState,
        namespace: &str,
        mount: &str,
        prior: &RecordStateRootV6,
        next: &RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<Option<Self>, AuthError> {
        let deadline = OriginalDeadline::capture().map_err(|_| unavailable())?;
        deadline.check().map_err(|_| unavailable())?;
        if !live() || mount.is_empty() || !mount.ends_with('/') {
            return Err(unavailable());
        }
        validate_namespace(namespace)?;
        prior.validate().map_err(|_| unavailable())?;
        next.validate().map_err(|_| unavailable())?;
        let before = canonical(source)?;
        let mut expected = source.clone();
        expected.prune_rate_limit_quotas_mount(namespace, mount);
        expected.validate_rate_limit_quota_state(Some(source))?;
        let expected = canonical(&expected)?;
        let after = canonical(candidate)?;
        // Config, other namespaces/mounts, bearer state, policies, clocks,
        // sticky reader markers and revision allocation all stay exact.
        if after.as_slice() != expected.as_slice() {
            return Err(unavailable());
        }
        let source_auth = auth_owner(prior)?;
        let target_auth = auth_owner(next)?;
        if source_auth.total_bytes != before.len() as u64
            || source_auth.digest
                != prior
                    .owner_digest(OwnerDomain::Auth, &before)
                    .map_err(|_| unavailable())?
            || target_auth.total_bytes != after.len() as u64
            || target_auth.digest
                != next
                    .owner_digest(OwnerDomain::Auth, &after)
                    .map_err(|_| unavailable())?
            || !live()
        {
            return Err(unavailable());
        }
        deadline.check().map_err(|_| unavailable())?;
        if before.as_slice() == after.as_slice() {
            // No selector was retired. Preserve the engine owner's original
            // requirement that Auth remains byte-for-byte unchanged.
            return Ok(None);
        }
        Ok(Some(Self {
            namespace: namespace.into(),
            mount: mount.into(),
            source_identity: prior.identity().map_err(|_| unavailable())?,
            target_identity: next.identity().map_err(|_| unavailable())?,
            source_auth: source_auth.clone(),
            target_auth: target_auth.clone(),
            source_auth_digest: crate::crypto::digest(&before),
            target_auth_digest: crate::crypto::digest(&after),
            deadline,
        }))
    }

    pub(crate) fn check_auth_candidates(
        &self,
        source: &AuthState,
        candidate: &AuthState,
        live: &impl Fn() -> bool,
    ) -> Result<(), AuthError> {
        self.deadline.check().map_err(|_| unavailable())?;
        if !live()
            || crate::crypto::digest(&canonical(source)?) != self.source_auth_digest
            || crate::crypto::digest(&canonical(candidate)?) != self.target_auth_digest
        {
            return Err(unavailable());
        }
        self.deadline.check().map_err(|_| unavailable())?;
        live().then_some(()).ok_or_else(unavailable)
    }

    /// Consume the exact removal in the actual engine owner's local root
    /// comparison. Its stored expected root remains the complete real target;
    /// no normalized root is published or used as a delivery checkpoint.
    pub(crate) fn normalize_owned_disable(
        self,
        namespace: &str,
        mount: &str,
        prior: &RecordStateRootV6,
        next: &mut RecordStateRootV6,
        live: &impl Fn() -> bool,
    ) -> Result<(), AuthError> {
        self.deadline.check().map_err(|_| unavailable())?;
        if !live()
            || namespace != self.namespace
            || mount != self.mount
            || prior.identity().map_err(|_| unavailable())? != self.source_identity
            || next.identity().map_err(|_| unavailable())? != self.target_identity
            || auth_owner(prior)? != &self.source_auth
            || auth_owner(next)? != &self.target_auth
        {
            return Err(unavailable());
        }
        let actual = next
            .owners
            .iter_mut()
            .find(|owner| owner.domain == OwnerDomain::Auth)
            .ok_or_else(unavailable)?;
        actual.owner = self.source_auth;
        self.deadline.check().map_err(|_| unavailable())?;
        live().then_some(()).ok_or_else(unavailable)
    }
}
