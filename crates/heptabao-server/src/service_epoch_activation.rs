//! Replay-epoch publication invalidates admitted external observations.
//! This is transient process authority; no new persisted field is introduced.
use super::*;

impl Service {
    pub(super) fn prepare_epoch_activation(
        &mut self,
        target_epoch: u64,
        already_committed: bool,
    ) -> Result<Option<String>, Response> {
        self.prepare_epoch_activation_with(target_epoch, already_committed, crypto::random::<16>)
    }

    fn prepare_epoch_activation_with(
        &mut self,
        target_epoch: u64,
        already_committed: bool,
        random: impl FnOnce() -> Result<[u8; 16], &'static str>,
    ) -> Result<Option<String>, Response> {
        let current = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        if current.replay_epoch == target_epoch {
            return Ok(None);
        }
        match random() {
            Ok(bytes) => Ok(Some(hex(&bytes))),
            Err(error) => {
                if already_committed {
                    // We cannot retract the committed authority. Fail closed
                    // until reopen instead of keeping the old activation live.
                    self.recovery_required = true;
                    self.ha_read_cache = None;
                }
                Err(Response::error(503, error))
            }
        }
    }

    pub(super) fn install_epoch_activation(&mut self, activation: Option<String>) {
        if let Some(activation) = activation {
            self.ha_read_cache = None;
            self.unseal_nonce = activation;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Root, bootstrap};

    #[test]
    fn epoch_random_failure_is_prepublication_and_fences_already_committed_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        for already_committed in [false, true] {
            let root = Root::new();
            let mut service = root.service()?;
            bootstrap(&mut service)?;
            let nonce = service.unseal_nonce.clone();
            let durable = service.durable.as_ref().ok_or("durable")?;
            let generation = durable.generation();
            let saved_root = durable.get("system", "state")?;
            let target_epoch = durable.replay_epoch().checked_add(1).ok_or("epoch")?;
            let response =
                service.prepare_epoch_activation_with(target_epoch, already_committed, || {
                    Err("injected entropy failure")
                });
            assert!(matches!(response, Err(error) if error.status == 503));
            assert_eq!(service.unseal_nonce, nonce);
            assert_eq!(service.recovery_required, already_committed);
            let durable = service.durable.as_ref().ok_or("durable")?;
            assert_eq!(durable.generation(), generation);
            assert_eq!(durable.get("system", "state")?, saved_root);
            assert_eq!(durable.replay_epoch() + 1, target_epoch);
        }
        Ok(())
    }
}
