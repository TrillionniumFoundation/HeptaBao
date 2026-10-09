//! Closed staged import owned by the existing engine transaction.
use super::*;

impl EngineState {
    pub(crate) fn has_kv2_lossless_state(&self) -> bool {
        self.kv2_lossless_format.is_some()
            || self.namespaces.values().any(|namespace| {
                namespace.mounts.values().any(|mount| {
                    matches!(&mount.backend, Backend::Kv2(engine) if engine.has_lossless_import_state())
                })
            })
    }

    pub(crate) fn validate_kv2_lossless_state(&self, previous: Option<&Self>) -> Result<()> {
        let mut present = false;
        for namespace in self.namespaces.values() {
            for mount in namespace.mounts.values() {
                if let Backend::Kv2(engine) = &mount.backend {
                    engine.validate_lossless_state()?;
                    present |= engine.has_lossless_import_state();
                }
            }
        }
        if self.kv2_lossless_format.is_some_and(|format| format != 1)
            || present && self.kv2_lossless_format != Some(1)
            || previous.is_some_and(|old| old.kv2_lossless_format == Some(1))
                && self.kv2_lossless_format != Some(1)
        {
            return Err(error(503, "invalid KV2 lossless format custody"));
        }
        Ok(())
    }

    /// A complete candidate is validated before touching the original state.
    /// The caller must publish this candidate under its existing Service owner.
    pub(crate) fn stage_openbao_kv2_import(
        &mut self,
        namespace: &str,
        requested: &str,
        bundle: &[u8],
    ) -> Result<EngineResponse> {
        let canonical = canonical_secret_mount(requested.trim_end_matches('/'))?;
        if requested != canonical && requested != format!("{canonical}/") {
            return Err(bad("KV2 import mount must be canonical"));
        }
        self.validate_kv2_lossless_state(None)?;
        let name = format!("{canonical}/");
        let imported = kv::Kv2::from_lossless_import_json(bundle)?;
        let mut candidate = self.clone();
        let owner = candidate
            .namespaces
            .get_mut(namespace)
            .ok_or_else(not_found)?;
        let mount = owner.mounts.get_mut(&name).ok_or_else(not_found)?;
        let Backend::Kv2(current) = &mount.backend else {
            return Err(bad("KV2 import requires an existing native KV2 mount"));
        };
        if !current.is_pristine_for_import() {
            return Err(error(409, "KV2 import requires a pristine empty mount"));
        }
        let revision = next_mount_revision(mount.revision)?;
        mount.backend = Backend::Kv2(imported);
        mount.revision = revision;
        candidate.kv2_lossless_format = Some(1);
        candidate.validate_kv2_lossless_state(Some(self))?;
        // Bound the whole staged owner before assignment, including the
        // original unaffected namespaces and other native engine state.
        let _encoded = crate::secret_serde::to_vec(&candidate, crate::MAX_APPLICATION_STATE_BYTES)
            .map_err(|_| error(507, "KV2 import owner exceeds serialization capacity"))?;
        *self = candidate;
        Ok(empty(true))
    }
}
