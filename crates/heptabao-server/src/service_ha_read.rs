//! Reuse only HA materialization already bound to this admitted local state.
use super::*;
use crate::ha::{CommittedApplicationState, CommittedRecordState, ValidatedReadCursor};
use crate::state_record_root::{RecordStateRoot, StateIdentity};

#[derive(Clone, Eq, PartialEq)]
struct LocalReadIdentity {
    records_v5: bool,
    digest: [u8; 32],
    replay_epoch: u64,
    durable_generation: u64,
    activation_nonce: String,
}

pub(super) struct HaReadCache {
    cursor: ValidatedReadCursor,
    local: LocalReadIdentity,
}

impl Service {
    fn local_ha_read_identity(&self) -> Option<LocalReadIdentity> {
        let state = self.state.as_ref()?;
        let durable = self.durable.as_ref()?;
        if self.recovery_required
            || durable.recovery_required()
            || self.barrier_key.is_none()
            || durable.replay_epoch() != state.replay_epoch
        {
            return None;
        }
        let digest = self.state_digest?;
        if let Some(root) = self.record_root.as_ref()
            && root.identity().ok()? != StateIdentity::RecordsV5(digest)
        {
            return None;
        }
        Some(LocalReadIdentity {
            records_v5: self.record_root.is_some(),
            digest,
            replay_epoch: state.replay_epoch,
            durable_generation: durable.generation(),
            activation_nonce: self.unseal_nonce.clone(),
        })
    }

    pub(super) fn reusable_ha_cursor(&self) -> Option<&ValidatedReadCursor> {
        let cache = self.ha_read_cache.as_ref()?;
        (self.local_ha_read_identity().as_ref() == Some(&cache.local)).then_some(&cache.cursor)
    }

    pub(super) fn cache_verified_ha_state(
        &mut self,
        committed: &CommittedApplicationState,
    ) -> Result<(), Response> {
        self.ha_read_cache = None;
        let Some(cursor) = committed.read_cursor.as_ref() else {
            return Ok(());
        };
        let Some(local) = self.local_ha_read_identity() else {
            return Ok(());
        };
        if local.records_v5 || local.digest != committed.digest {
            return Err(Response::error(
                503,
                "HA read verification differs from admitted state",
            ));
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let record = durable
            .get("system", "state")
            .map_err(|_| Response::error(503, "local owner publication is unavailable"))?
            .ok_or_else(|| Response::error(503, "local owner publication is absent"))?;
        let manifest = owner_store::decode_manifest(record.expose())
            .map_err(|_| Response::error(503, "local owner publication is invalid"))?;
        // Historical local framing remains readable. It cannot establish the
        // V4 canonical publication proof required for this optimization.
        let Some(manifest) = manifest else {
            return Ok(());
        };
        manifest
            .verify_logical(&committed.bytes)
            .map_err(|_| Response::error(503, "local and HA logical state diverge"))?;
        if manifest.state_schema() != state.schema
            || manifest.cluster_id() != state.cluster_id
            || manifest.replay_epoch() != local.replay_epoch
            || Some(
                manifest
                    .canonical_digest()
                    .map_err(|_| Response::error(503, "local owner identity is invalid"))?,
            ) != committed.owner_manifest_digest
        {
            return Err(Response::error(
                503,
                "local and HA owner publication identities diverge",
            ));
        }
        self.ha_read_cache = Some(HaReadCache {
            cursor: cursor.clone(),
            local,
        });
        Ok(())
    }
    pub(super) fn cache_verified_ha_records(
        &mut self,
        committed: &CommittedRecordState,
    ) -> Result<(), Response> {
        self.ha_read_cache = None;
        let Some(cursor) = committed.read_cursor.as_ref() else {
            return Ok(());
        };
        let Some(local) = self.local_ha_read_identity() else {
            return Ok(());
        };
        if !local.records_v5 || committed.identity != StateIdentity::RecordsV5(local.digest) {
            return Err(Response::error(
                503,
                "HA record identity differs from admitted state",
            ));
        }
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let durable = self
            .durable
            .as_ref()
            .ok_or_else(|| Response::error(503, "server is sealed"))?;
        let published = durable
            .get("system", "state")
            .map_err(|_| Response::error(503, "local record publication is unavailable"))?
            .ok_or_else(|| Response::error(503, "local record publication is absent"))?;
        let root = RecordStateRoot::decode(published.expose())
            .map_err(|_| Response::error(503, "local record publication is invalid"))?;
        if published.expose() != committed.root_bytes.as_slice()
            || root
                .identity()
                .map_err(|_| Response::error(503, "local root identity is invalid"))?
                != committed.identity
            || root.state_schema != state.schema
            || root.cluster_id != state.cluster_id
            || root.replay_epoch != local.replay_epoch
        {
            return Err(Response::error(
                503,
                "local and HA record publications diverge",
            ));
        }
        // Service calls this only after it has authenticated the complete graph
        // and admitted/persisted that exact root locally. An apply during graph
        // loading may still yield a valid immutable read, but never a warm cursor.
        let ha = self
            .ha
            .as_ref()
            .ok_or_else(|| Response::error(503, "HA is unavailable"))?;
        if !ha
            .lock()
            .map_err(|_| Response::error(503, "HA control state is unavailable"))?
            .record_cursor_current(cursor)
        {
            return Ok(());
        }
        self.ha_read_cache = Some(HaReadCache {
            cursor: cursor.clone(),
            local,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn verified(service: &Service) -> TestResult<CommittedApplicationState> {
        let state = service.state.as_ref().ok_or("missing state")?;
        let durable = service.durable.as_ref().ok_or("missing durable state")?;
        let record = durable.get("system", "state")?.ok_or("missing manifest")?;
        let manifest =
            owner_store::decode_manifest(record.expose())?.ok_or("missing V4 manifest")?;
        let bytes = owner_store::serialize_owner(state)?;
        crate::ha::read_tests::fully_verified_fixture(&bytes, manifest.canonical_digest()?)
    }

    fn cache(service: &mut Service, committed: &CommittedApplicationState) -> TestResult {
        service
            .cache_verified_ha_state(committed)
            .map_err(|_| "cache admission failed")?;
        assert!(service.reusable_ha_cursor().is_some());
        Ok(())
    }

    #[test]
    fn cache_is_bound_to_live_digest_epoch_generation_and_recovery_state() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (_, token) = bootstrap(&mut service)?;
        let committed = verified(&service)?;
        cache(&mut service, &committed)?;
        service.recovery_required = true;
        assert!(service.reusable_ha_cursor().is_none());
        service.recovery_required = false;
        let original_digest = service.state_digest.replace([0; 32]);
        assert!(service.reusable_ha_cursor().is_none());
        service.state_digest = original_digest;
        service.state.as_mut().ok_or("missing state")?.replay_epoch += 1;
        assert!(service.reusable_ha_cursor().is_none());
        service.state.as_mut().ok_or("missing state")?.replay_epoch -= 1;
        assert!(service.reusable_ha_cursor().is_some());
        // An otherwise identical local publication changes durable generation.
        let state = service.state.clone().ok_or("missing state")?;
        service
            .commit_state(&state)
            .map_err(|_| "same-state publication failed")?;
        assert!(service.reusable_ha_cursor().is_none());
        let next = verified(&service)?;
        cache(&mut service, &next)?;
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/change",
                &token,
                json!({"data":{"value":"changed"}})
            )
            .status,
            200
        );
        assert!(service.reusable_ha_cursor().is_none());
        Ok(())
    }

    #[test]
    fn seal_unseal_and_restart_never_restore_process_local_read_evidence() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        let (key, token) = bootstrap(&mut service)?;
        let committed = verified(&service)?;
        cache(&mut service, &committed)?;
        assert_eq!(
            call(&mut service, "POST", "sys/seal", &token, json!({})).status,
            204
        );
        assert!(service.reusable_ha_cursor().is_none());
        assert!(service.ha_read_cache.is_none());
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert!(service.reusable_ha_cursor().is_none());
        let current = verified(&service)?;
        cache(&mut service, &current)?;
        drop(service);
        let mut reopened = root.service()?;
        assert_eq!(
            call(&mut reopened, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert!(reopened.reusable_ha_cursor().is_none());
        Ok(())
    }

    #[test]
    fn same_state_digest_with_wrong_owner_identity_cannot_become_cached() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        bootstrap(&mut service)?;
        let good = verified(&service)?;
        cache(&mut service, &good)?;
        let wrong = crate::ha::read_tests::fully_verified_fixture(&good.bytes, [9; 32])?;
        assert_eq!(wrong.digest, good.digest);
        let error = service
            .cache_verified_ha_state(&wrong)
            .err()
            .ok_or("wrong owner identity was accepted")?;
        assert_eq!(error.status, 503);
        assert!(service.ha_read_cache.is_none());
        Ok(())
    }

    #[test]
    fn incomplete_local_recovery_cannot_admit_verified_remote_cursor() -> TestResult {
        let root = Root::new();
        let mut service = root.service()?;
        bootstrap(&mut service)?;
        let committed = verified(&service)?;
        service.recovery_required = true;
        service
            .cache_verified_ha_state(&committed)
            .map_err(|_| "unexpected cache error")?;
        assert!(service.reusable_ha_cursor().is_none());
        assert!(service.ha_read_cache.is_none());
        service.recovery_required = false;
        service.state.as_mut().ok_or("missing state")?.replay_epoch += 1;
        service
            .cache_verified_ha_state(&committed)
            .map_err(|_| "unexpected cache error")?;
        assert!(service.ha_read_cache.is_none());
        Ok(())
    }
}
