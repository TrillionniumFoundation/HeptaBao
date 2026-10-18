//! Monotone timestamps only; protected mount epochs, revocations, catalogs,
//! registrations and reader floors remain subject to their original checks.
use super::*;

impl EngineState {
    pub(crate) fn inherit_native_snapshot_clocks(&mut self, current: &Self) -> Result<()> {
        self.lease_clock = self.lease_clock.max(current.lease_clock);
        self.sdk_lease_clock = self.sdk_lease_clock.max(current.sdk_lease_clock);
        self.pki_revocation_clock = self.pki_revocation_clock.max(current.pki_revocation_clock);
        self.kubernetes_artifact_clock = self.kubernetes_artifact_clock.max(current.kubernetes_artifact_clock);
        self.acme_clock = self.acme_clock.max(current.acme_clock);
        self.validate_sdk_lease_clock(Some(current))?;
        self.validate_pki_revocation_clock(Some(current))?;
        self.validate_kubernetes_artifact_clock(Some(current))
    }
}
