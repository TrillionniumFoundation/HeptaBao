//! Monotone timestamps only; protected mount epochs, revocations, catalogs,
//! registrations and reader floors remain subject to their original checks.
use super::*;

impl EngineState {
    /// Preserve only a live, already-owned global KV2 producer floor when the
    /// authenticated incoming paged graph contains no KV2 history at all.
    /// This changes neither a mount cell nor any payload/configuration graph.
    /// Actual archive authentication and publication remain the Service owner.
    #[cfg(any(test, feature = "native-v6-storage"))]
    pub(crate) fn retain_empty_native_snapshot_kv2_floor(
        &mut self,
        current: &Self,
        parent: &crate::state_records::AddressKey,
        roots: &[crate::state_record_root_v6::Kv2GraphRef],
        check: &impl Fn() -> std::result::Result<(), crate::state_records::RecordError>,
    ) -> Result<bool> {
        let rejected = || error(503, "native empty snapshot producer floor is unverified");
        check().map_err(|_| rejected())?;
        self.validate_kv2_lossless_state(None)?;
        current.validate_kv2_lossless_state(None)?;
        if self.kv2_lossless_format.is_some() || current.kv2_lossless_format != Some(1) {
            return Ok(false);
        }
        let expected: BTreeMap<_, _> = roots
            .iter()
            .map(|root| (root.scope.clone(), root))
            .collect();
        if expected.len() != roots.len() {
            return Err(rejected());
        }
        let mut seen = BTreeSet::new();
        for (namespace, owner) in &self.namespaces {
            for (mount, descriptor) in &owner.mounts {
                check().map_err(|_| rejected())?;
                match &descriptor.backend {
                    Backend::Kv2Native(view) => {
                        let scope = crate::state_record_root_v6::MountScope {
                            namespace: namespace.clone(),
                            mount: mount.clone(),
                            incarnation: descriptor.incarnation,
                        };
                        let root = expected.get(&scope).ok_or_else(rejected)?;
                        if root.graph_format != kv2_native_records::PAGED_NATIVE_FORMAT
                            || root.logical_payload_bytes != 0
                            || !view
                                .is_authenticated_empty_for_marker(
                                    parent,
                                    scope.borrowed(),
                                    &root.root,
                                    check,
                                )
                                .map_err(|_| rejected())?
                        {
                            return Err(rejected());
                        }
                        seen.insert(scope);
                    }
                    Backend::Kv2(_) => return Err(rejected()),
                    _ => {}
                }
            }
        }
        if seen.len() != expected.len() {
            return Err(rejected());
        }
        check().map_err(|_| rejected())?;
        self.kv2_lossless_format = Some(1);
        Ok(true)
    }

    pub(crate) fn inherit_native_snapshot_clocks(&mut self, current: &Self) -> Result<()> {
        self.lease_clock = self.lease_clock.max(current.lease_clock);
        self.sdk_lease_clock = self.sdk_lease_clock.max(current.sdk_lease_clock);
        self.pki_revocation_clock = self.pki_revocation_clock.max(current.pki_revocation_clock);
        self.kubernetes_artifact_clock = self
            .kubernetes_artifact_clock
            .max(current.kubernetes_artifact_clock);
        self.acme_clock = self.acme_clock.max(current.acme_clock);
        self.validate_sdk_lease_clock(Some(current))?;
        self.validate_pki_revocation_clock(Some(current))?;
        self.validate_kubernetes_artifact_clock(Some(current))
    }
}
