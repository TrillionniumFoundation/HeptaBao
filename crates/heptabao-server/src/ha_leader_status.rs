//! Diagnosis only: never replace ReadIndex or authenticated state admission.
use super::*;

impl HaProcess {
    pub(crate) fn leader_status(
        &self,
    ) -> Result<heptabao_raft_runtime::LocalLeaderObservation, String> {
        self.node
            .as_ref()
            .ok_or_else(|| "HA process is shut down".to_owned())?
            .local_leader_observation()
            .map_err(|_| "HA leader observation is unavailable".to_owned())
    }
}
