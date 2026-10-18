//! Install and prove native views against actual metadata ownership.
//! These helpers confer no publication, unseal, or HA authority.
use super::*;
use crate::state_record_root_v6::{Kv2GraphRef, MountScope};

#[cfg(any(test, feature = "fixture-native-v6-service"))]
impl EngineState {
    pub(crate) fn install_native_views(
        &mut self,
        views: BTreeMap<MountScope, NativeReadView>,
    ) -> Result<()> {
        let scopes: Vec<_> = views.keys().cloned().collect();
        self.validate_v6_kv2_placeholders(&scopes)?;
        // Complete all view/scope checks before cloning or replacing owners.
        // A detached fixture with no authenticated cache is not installable.
        for (scope, view) in &views {
            if !view
                .cached_scope_matches(scope.borrowed())
                .map_err(|_| error(503, "native KV2 view scope rejected"))?
            {
                return Err(error(503, "native KV2 view lacks an authenticated graph"));
            }
        }
        let mut candidate = self.clone();
        for (scope, view) in views {
            let mount = candidate
                .namespaces
                .get_mut(&scope.namespace)
                .and_then(|owner| owner.mounts.get_mut(&scope.mount))
                .ok_or_else(|| error(503, "native KV2 metadata owner disappeared"))?;
            if mount.incarnation != scope.incarnation {
                return Err(error(503, "native KV2 metadata incarnation changed"));
            }
            mount.backend = Backend::Kv2Native(view);
        }
        *self = candidate;
        Ok(())
    }

    /// Advance only a detached candidate's cache to its exact projected roots.
    /// The Service writer must separately authenticate and atomically publish
    /// those roots. This prevents later point writes from reencoding payloads
    /// introduced by earlier successful candidates.
    #[cfg(test)]
    pub(crate) fn advance_native_caches(
        &mut self,
        parent: &AddressKey,
        roots: &[Kv2GraphRef],
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        self.validate_native_roots(parent, roots, check)?;
        let mut candidate = self.clone();
        for reference in roots {
            check()?;
            let descriptor = candidate
                .namespaces
                .get_mut(&reference.scope.namespace)
                .and_then(|owner| owner.mounts.get_mut(&reference.scope.mount))
                .ok_or(RecordError::Missing)?;
            let Backend::Kv2Native(view) = &mut descriptor.backend else {
                return Err(RecordError::Corrupt);
            };
            view.advance_authenticated_cache(
                parent,
                reference.scope.borrowed(),
                &reference.root,
                check,
            )?;
        }
        check()?;
        *self = candidate;
        check()
    }

    /// Prove the live runtime owner, including pending selected-cell changes,
    /// equals the exact authenticated root. No whole owner is serialized.
    pub(crate) fn validate_native_roots(
        &self,
        parent: &AddressKey,
        roots: &[Kv2GraphRef],
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<()> {
        check()?;
        let expected: BTreeMap<_, _> = roots
            .iter()
            .map(|root| (root.scope.clone(), root))
            .collect();
        if expected.len() != roots.len() {
            return Err(RecordError::Corrupt);
        }
        let mut actual = BTreeSet::new();
        for (namespace, owner) in &self.namespaces {
            for (mount, descriptor) in &owner.mounts {
                check()?;
                match &descriptor.backend {
                    Backend::Kv2Native(view) => {
                        let scope = MountScope {
                            namespace: namespace.clone(),
                            mount: mount.clone(),
                            incarnation: descriptor.incarnation,
                        };
                        let reference = expected.get(&scope).ok_or(RecordError::Missing)?;
                        if (reference.graph_format != NATIVE_FORMAT
                            && reference.graph_format != PAGED_NATIVE_FORMAT)
                            || (reference.graph_format == PAGED_NATIVE_FORMAT) != view.is_paged()
                            || view.logical_payload_bytes()? != reference.logical_payload_bytes
                            || !view.matches_authenticated_root(
                                parent,
                                scope.borrowed(),
                                &reference.root,
                                check,
                            )?
                        {
                            return Err(RecordError::Corrupt);
                        }
                        actual.insert(scope);
                    }
                    // A live V6 reader must never use its pristine metadata
                    // placeholder as fallback data or configuration.
                    Backend::Kv2(_) => return Err(RecordError::Corrupt),
                    _ => {}
                }
                check()?;
            }
        }
        if actual.len() != expected.len() {
            return Err(RecordError::Corrupt);
        }
        check()
    }

    /// Project each live native view once, including its pending changes, and
    /// prove the resulting complete references equal the authenticated roots.
    /// The ordinary projection also accepts migration placeholders, so bind
    /// actual live owners before calling it. No cached root is a substitute for
    /// its checked encoder; physical source/AEAD and Service authority remain
    /// the caller's separate prerequisites.
    pub(crate) fn project_checked_native_roots(
        &self,
        parent: &AddressKey,
        roots: &[Kv2GraphRef],
        native_kv2_format: u32,
        check: &impl Fn() -> CodecResult<()>,
    ) -> CodecResult<(EngineState, Vec<Kv2GraphRef>)> {
        check()?;
        let format = match native_kv2_format {
            1 => NATIVE_FORMAT,
            2 => PAGED_NATIVE_FORMAT,
            _ => return Err(RecordError::Invalid),
        };
        let expected: BTreeMap<_, _> = roots
            .iter()
            .map(|root| (root.scope.clone(), root))
            .collect();
        if expected.len() != roots.len() {
            return Err(RecordError::Corrupt);
        }
        let mut actual = BTreeSet::new();
        for (namespace, owner) in &self.namespaces {
            for (mount, descriptor) in &owner.mounts {
                check()?;
                match &descriptor.backend {
                    Backend::Kv2Native(view) => {
                        let scope = MountScope {
                            namespace: namespace.clone(),
                            mount: mount.clone(),
                            incarnation: descriptor.incarnation,
                        };
                        let reference = expected.get(&scope).ok_or(RecordError::Missing)?;
                        if reference.graph_format != format
                            || view.is_paged() != (native_kv2_format == 2)
                            || view.logical_payload_bytes()? != reference.logical_payload_bytes
                        {
                            return Err(RecordError::Corrupt);
                        }
                        actual.insert(scope);
                    }
                    Backend::Kv2(_) => return Err(RecordError::Corrupt),
                    _ => {}
                }
                check()?;
            }
        }
        if actual.len() != expected.len() {
            return Err(RecordError::Corrupt);
        }
        check()?;
        // Keep the existing per-mount and aggregate bounds, checked encoding
        // of pending edits and per-object visitor gates. Only the duplicate
        // encode formerly performed by validate_native_roots is eliminated.
        let (opaque, projected) = if native_kv2_format == 2 {
            self.project_v6_native_paged(parent, check, |_, _| check())
        } else {
            self.project_v6_native(parent, check, |_, _| check())
        }?;
        check()?;
        if projected.len() != roots.len() {
            return Err(RecordError::Corrupt);
        }
        for (observed, expected) in projected.iter().zip(roots) {
            check()?;
            if observed.scope != expected.scope
                || observed.graph_format != expected.graph_format
                || observed.logical_payload_bytes != expected.logical_payload_bytes
                || observed.root != expected.root
            {
                return Err(RecordError::Corrupt);
            }
            check()?;
        }
        check()?;
        Ok((opaque, projected))
    }
}

#[cfg(test)]
#[path = "kv2_native_install_projection_tests.rs"]
mod projection_tests;
