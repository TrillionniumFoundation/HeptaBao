//! A local Shamir unseal status is not an actor, lease or leader response.
//! Keep the original request clock and completed local owner through audit,
//! without converting a standby status into a second Raft publication.
use super::*;
use crate::state_record_root::{RecordStateRoot, StateIdentity};
use std::time::Instant;

pub(super) enum LocalUnsealCompletion {
    Ready(Box<LocalUnsealOwner>),
    Rejected(Response),
}

// Affine and process-local: no Clone, wire encoding, principal or commit grant.
pub(super) struct LocalUnsealOwner {
    clock: RequestClock,
    deadline: Option<Instant>,
    seal: SealMetadata,
    nonce: Zeroizing<String>,
    barrier_digest: [u8; 32],
    ha: Option<Arc<Mutex<HaProcess>>>,
    identity: StateIdentity,
    generation: u64,
    logical: Zeroizing<Vec<u8>>,
    published: Zeroizing<Vec<u8>>,
}

fn unavailable() -> Response {
    Response::error(503, "local unseal completion authority is unavailable")
}

impl LocalUnsealOwner {
    fn capture(
        service: &mut Service,
        clock: Option<RequestClock>,
        deadline: Option<Instant>,
    ) -> Result<Self, Response> {
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        let publication = durable
            .get("system", "state")
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let owner = Self {
            clock: clock.ok_or_else(|| Response::error(503, "trusted token clock is required"))?,
            deadline,
            seal: service.seal.clone().ok_or_else(unavailable)?,
            nonce: Zeroizing::new(service.unseal_nonce.clone()),
            barrier_digest: crypto::digest(
                service
                    .barrier_key
                    .as_ref()
                    .ok_or_else(unavailable)?
                    .as_slice(),
            ),
            ha: service.ha.as_ref().map(Arc::clone),
            identity: service.current_state_identity()?,
            generation: durable.generation(),
            logical: owner_store::serialize_owner(service.state.as_ref().ok_or_else(unavailable)?)
                .map_err(state_serialization_error)?,
            published: Zeroizing::new(publication.expose().to_vec()),
        };
        owner.check(service)?;
        Ok(owner)
    }

    fn live(&self) -> Result<(), Response> {
        let deadline = match (self.deadline, crate::request_deadline::current()) {
            (Some(original), Some(current)) => Some(original.min(current)),
            (original, current) => original.or(current),
        };
        if deadline.is_some_and(|end| Instant::now() >= end) {
            return Err(Response::error(
                503,
                "local unseal original deadline elapsed",
            ));
        }
        // Observe the same original trusted clock. Do not update a private floor,
        // create AuthorityTime, resample wall time, or confer actor qualification.
        self.clock
            .observed_at()
            .map_err(|_| Response::error(503, "local unseal original clock unavailable"))?;
        Ok(())
    }

    fn check_instance(&self, service: &Service) -> Result<(), Response> {
        self.live()?;
        let same_ha = match (&self.ha, &service.ha) {
            (None, None) => true,
            (Some(original), Some(current)) => Arc::ptr_eq(original, current),
            _ => false,
        };
        if service.recovery_required
            || service.audit_failed
            || service.openbao_wrapper_owner.is_some()
            || self.seal.schema != 1
            || self.seal.is_wrapper()
            || service.seal.as_ref() != Some(&self.seal)
            || service.unseal_nonce != *self.nonce
            || !same_ha
            || service
                .barrier_key
                .as_ref()
                .is_none_or(|key| crypto::digest(key.as_slice()) != self.barrier_digest)
            || service.current_state_identity()? != self.identity
            || load_seal_metadata(&service.data_dir)
                .ok()
                .flatten()
                .as_ref()
                != Some(&self.seal)
        {
            return Err(unavailable());
        }
        self.seal.validate().map_err(|_| unavailable())?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        if state.auth.has_recovery_state()
            || !state.has_token_api_precision_state()
                && !state.engines.has_kubernetes_opaque_artifact_state()
        {
            return Err(unavailable());
        }
        state.namespace_leases.validate()?;
        state.validate_format()?;
        if owner_store::serialize_owner(state)
            .map_err(state_serialization_error)?
            .as_slice()
            != self.logical.as_slice()
        {
            return Err(unavailable());
        }
        self.live()
    }

    fn check(&self, service: &mut Service) -> Result<(), Response> {
        self.check_instance(service)?;
        service
            .durable
            .as_mut()
            .ok_or_else(unavailable)?
            .verify_live_ownership()
            .map_err(|_| unavailable())?;
        let durable = service.durable.as_ref().ok_or_else(unavailable)?;
        if durable.recovery_required() || durable.generation() != self.generation {
            return Err(unavailable());
        }
        let publication = durable
            .get("system", "state")
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        if publication.expose() != self.published.as_slice() {
            return Err(unavailable());
        }
        // Reauthenticate the complete actual durable graph. Neither a warm
        // in-memory digest nor an unchanged local generation proves the owner.
        let (loaded, _, _) = Service::load_state_from_durable(durable)?;
        if owner_store::serialize_owner(&loaded)
            .map_err(state_serialization_error)?
            .as_slice()
            != self.logical.as_slice()
            || durable.replay_epoch() != loaded.replay_epoch
        {
            return Err(unavailable());
        }
        match self.identity {
            StateIdentity::Legacy(digest) => {
                if records::decode_root(publication.expose())?.is_some()
                    || crypto::digest(&self.logical) != digest
                {
                    return Err(unavailable());
                }
                if let Some(manifest) =
                    owner_store::decode_manifest(publication.expose()).map_err(|_| unavailable())?
                {
                    manifest
                        .verify_logical(&self.logical)
                        .map_err(|_| unavailable())?;
                }
            }
            StateIdentity::RecordsV5(_) => {
                let root =
                    RecordStateRoot::decode(publication.expose()).map_err(|_| unavailable())?;
                if root.identity().map_err(|_| unavailable())? != self.identity
                    || root.state_schema != loaded.schema
                    || root.cluster_id != loaded.cluster_id
                    || root.replay_epoch != loaded.replay_epoch
                {
                    return Err(unavailable());
                }
            }
        }
        service
            .durable
            .as_mut()
            .ok_or_else(unavailable)?
            .verify_live_ownership()
            .map_err(|_| unavailable())?;
        if service
            .durable
            .as_ref()
            .ok_or_else(unavailable)?
            .generation()
            != self.generation
        {
            return Err(unavailable());
        }
        self.check_instance(service)
    }

    fn check_response(&self, service: &mut Service, response: &Response) -> Result<(), Response> {
        self.check(service)?;
        if response.status != 200
            || !response.response_headers.is_empty()
            || response.consistency_index.is_some()
            || response.body != service.seal_status().body
            || response.body["sealed"] != false
        {
            return Err(unavailable());
        }
        self.live()
    }
}

impl Service {
    pub(super) fn capture_local_unseal_completion(
        &mut self,
        response: &Response,
        clock: Option<RequestClock>,
        deadline: Option<Instant>,
    ) {
        let selected = response.status == 200
            && response.body["sealed"] == false
            && self.openbao_wrapper_owner.is_none()
            && self
                .seal
                .as_ref()
                .is_some_and(|seal| seal.schema == 1 && !seal.is_wrapper())
            && self.state.as_ref().is_some_and(|state| {
                state.has_token_api_precision_state()
                    || state.engines.has_kubernetes_opaque_artifact_state()
            });
        if !selected {
            return;
        }
        // Construction is reached only from the actual local unseal call. The
        // original clock/deadline were captured before it could install any key.
        self.pending_local_unseal_completion = Some(
            match LocalUnsealOwner::capture(self, clock, deadline).and_then(|owner| {
                owner.check_response(self, response)?;
                Ok(owner)
            }) {
                Ok(owner) => LocalUnsealCompletion::Ready(Box::new(owner)),
                Err(error) => LocalUnsealCompletion::Rejected(error),
            },
        );
    }

    pub(super) fn complete_local_unseal_response(
        &mut self,
        completion: LocalUnsealCompletion,
        response: Response,
        fingerprint: &str,
        now: u64,
    ) -> Response {
        self.complete_local_unseal_response_with(completion, response, fingerprint, now, |_| {})
    }

    fn complete_local_unseal_response_with(
        &mut self,
        completion: LocalUnsealCompletion,
        mut response: Response,
        fingerprint: &str,
        now: u64,
        after_audit: impl FnOnce(&mut Self),
    ) -> Response {
        let owner = match completion {
            LocalUnsealCompletion::Ready(owner) => match owner.check_response(self, &response) {
                Ok(()) => Some(owner),
                Err(error) => {
                    response = error;
                    None
                }
            },
            LocalUnsealCompletion::Rejected(error) => {
                response = error;
                None
            }
        };
        // Mandatory audit remains mandatory. This path deliberately does not
        // mint a completed-forward receipt or an authoritative response index.
        if self
            .audit_event("response", fingerprint, now, Some(response.status))
            .is_err()
        {
            self.recovery_required = true;
            self.ha_activation = None;
            return Response::error(
                503,
                "response audit failed; outcome unknown; authoritative recovery required",
            );
        }
        after_audit(self);
        if let Some(owner) = owner
            && let Err(error) = owner.check_response(self, &response)
        {
            let status = error.status;
            response = error;
            if self
                .audit_event("response-veto", fingerprint, now, Some(status))
                .is_err()
            {
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "response audit failed; outcome unknown; authoritative recovery required",
                );
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::tests::{Root, bootstrap_unmounted};
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Fixture {
        service: Service,
        cluster: crate::ha::snapshot_test_support::Cluster,
        share: Zeroizing<String>,
        token: Zeroizing<String>,
        root: Root,
    }
    fn follower() -> Result<Fixture, Box<dyn std::error::Error>> {
        let root = Root::new();
        let mut service = root.service()?;
        let (share, token) = bootstrap_unmounted(&mut service)?;
        let minted = service.handle_request(ServiceRequest::new(
            "POST",
            "auth/token/create",
            "",
            &token,
            json!({"ttl":"1h"}),
        ));
        assert_eq!(minted.status, 200);
        assert!(
            service
                .state
                .as_ref()
                .ok_or("state")?
                .has_token_api_precision_state()
        );
        let cluster = crate::ha::snapshot_test_support::Cluster::new(
            &root.path.join("raft"),
            &service.state.as_ref().ok_or("state")?.cluster_id,
        )?;
        service.ha = Some(Arc::clone(&cluster.processes[0]));
        service
            .sync_from_ha()
            .map_err(|_| "actual precise HA anchor")?;
        drop(service);
        let mut service = root.service()?;
        service.ha = Some(Arc::clone(&cluster.processes[1]));
        Ok(Fixture {
            root,
            service,
            cluster,
            share: Zeroizing::new(share),
            token: Zeroizing::new(token),
        })
    }
    fn original_clock() -> Result<RequestClock, Box<dyn std::error::Error>> {
        RequestClock::anchored(
            SystemTime::now().duration_since(UNIX_EPOCH)?,
            Instant::now(),
        )
        .map_err(|_| "clock".into())
    }
    fn local_status(f: &mut Fixture) -> Result<Response, Box<dyn std::error::Error>> {
        let response = f.service.unseal(&json!({"key": f.share.as_str()}));
        assert_eq!(response.status, 200);
        assert_eq!(response.body["sealed"], false);
        Ok(response)
    }

    #[test]
    fn real_raft_local_unseal_precise_follower_audits_status_without_second_floor_writer()
    -> TestResult {
        let mut f = follower()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let (identity_before, _) = f.cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .application_identity_witness()?;
        let response = f.service.handle_request(ServiceRequest::new(
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": f.share.as_str()}),
        ));
        assert_eq!(response.status, 200);
        assert_eq!(response.body["sealed"], false);
        assert!(response.consistency_index.is_none());
        assert!(response.response_headers.is_empty());
        assert!(!f.service.recovery_required);
        let (identity_after, _) = f.cluster.processes[1]
            .lock()
            .map_err(|_| "HA")?
            .application_identity_witness()?;
        assert_eq!(
            identity_before, identity_after,
            "local status publishes no Raft floor"
        );
        let identity = f.service.current_state_identity().map_err(|_| "identity")?;
        let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
        let publication = f
            .service
            .durable
            .as_ref()
            .ok_or("durable")?
            .get("system", "state")?;
        let repeated = f.service.handle_request(ServiceRequest::new(
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": f.share.as_str()}),
        ));
        assert_eq!(repeated.status, 200);
        assert_eq!(
            f.service.current_state_identity().map_err(|_| "identity")?,
            identity
        );
        assert_eq!(
            f.service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(
            f.service
                .durable
                .as_ref()
                .ok_or("durable")?
                .get("system", "state")?,
            publication
        );
        // A local unseal capsule does not authorize ordinary token delivery.
        let lookup = f.service.handle_at(
            "GET",
            "auth/token/lookup-self",
            "",
            &f.token,
            json!({}),
            100,
        );
        assert_eq!(lookup.status, 503);
        assert!(f.service.pending_local_unseal_completion.is_none());
        Ok(())
    }

    #[test]
    fn real_raft_local_unseal_precise_missing_clock_is_denied_without_refunding_key_install()
    -> TestResult {
        let mut f = follower()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let response = f.service.handle_at(
            "POST",
            "sys/unseal",
            "",
            "",
            json!({"key": f.share.as_str()}),
            100,
        );
        assert_eq!(response.status, 503);
        assert_eq!(
            response.body["errors"][0],
            "trusted token clock is required"
        );
        assert!(f.service.state.is_some());
        assert!(f.service.barrier_key.is_some());
        assert!(!f.service.recovery_required);
        assert!(f.service.pending_local_unseal_completion.is_none());
        assert_eq!(f.service.seal_status().body["sealed"], false);
        Ok(())
    }

    #[test]
    fn real_raft_local_unseal_owner_rejects_nonce_key_ha_and_independent_durable_damage()
    -> TestResult {
        let mut f = follower()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(15),
        );
        let response = local_status(&mut f)?;
        let owner = LocalUnsealOwner::capture(
            &mut f.service,
            Some(original_clock()?),
            crate::request_deadline::current(),
        )
        .map_err(|_| "actual local owner")?;
        owner
            .check_response(&mut f.service, &response)
            .map_err(|_| "valid owner")?;
        f.service.unseal_nonce.push('x');
        assert!(owner.check_response(&mut f.service, &response).is_err());
        f.service.unseal_nonce.pop();
        f.service.barrier_key.as_mut().ok_or("key")?[0] ^= 1;
        assert!(owner.check_response(&mut f.service, &response).is_err());
        f.service.barrier_key.as_mut().ok_or("key")?[0] ^= 1;
        f.service.ha = Some(Arc::clone(&f.cluster.processes[2]));
        assert!(owner.check_response(&mut f.service, &response).is_err());
        f.service.ha = Some(Arc::clone(&f.cluster.processes[1]));
        owner
            .check_response(&mut f.service, &response)
            .map_err(|_| "restored original owner")?;
        f.service
            .durable
            .as_mut()
            .ok_or("durable")?
            .put(PutRequest::new(
                "local-unseal-negative",
                "system",
                "independent-damaged-publication",
                "state",
                crypto::digest(b"damaged-local-unseal"),
                Secret::new(b"damaged-local-unseal".to_vec())?,
            )?)?;
        assert!(owner.check_response(&mut f.service, &response).is_err());
        assert!(f.root.path.is_dir());
        Ok(())
    }

    #[test]
    fn real_raft_local_unseal_mandatory_audit_and_original_deadline_withhold_status() -> TestResult
    {
        let mut f = follower()?;
        {
            let _scope = crate::request_deadline::RequestDeadlineScope::enter(
                Instant::now() + Duration::from_secs(15),
            );
            let response = local_status(&mut f)?;
            let owner = LocalUnsealOwner::capture(
                &mut f.service,
                Some(original_clock()?),
                crate::request_deadline::current(),
            )
            .map_err(|_| "actual local owner")?;
            f.service.audit_capacity = f.service.audit.metadata()?.len();
            let denied = f.service.complete_local_unseal_response(
                LocalUnsealCompletion::Ready(Box::new(owner)),
                response,
                "audit-failure",
                100,
            );
            assert_eq!(denied.status, 503);
            assert!(f.service.recovery_required);
            assert!(
                f.service.barrier_key.is_some(),
                "committed key is never refunded"
            );
        }
        // A fresh independent instance is used after an audit fence.
        drop(f);
        let mut f = follower()?;
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(
            Instant::now() + Duration::from_secs(2),
        );
        let response = local_status(&mut f)?;
        let end = Instant::now() + Duration::from_millis(250);
        let _original = crate::request_deadline::RequestDeadlineScope::enter(end);
        let owner = LocalUnsealOwner::capture(
            &mut f.service,
            Some(original_clock()?),
            crate::request_deadline::current(),
        )
        .map_err(|_| "original bounded local owner")?;
        let generation = f.service.durable.as_ref().ok_or("durable")?.generation();
        let denied = f.service.complete_local_unseal_response_with(
            LocalUnsealCompletion::Ready(Box::new(owner)),
            response,
            "expired-after-audit",
            100,
            |_| {
                std::thread::sleep(
                    end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                );
            },
        );
        assert_eq!(denied.status, 503);
        assert_eq!(
            denied.body["errors"][0],
            "local unseal original deadline elapsed"
        );
        assert!(
            !f.service.recovery_required,
            "late local status denial is not durable corruption"
        );
        assert!(f.service.barrier_key.is_some());
        assert_eq!(
            f.service.durable.as_ref().ok_or("durable")?.generation(),
            generation
        );
        assert_eq!(f.service.seal_status().body["sealed"], false);
        Ok(())
    }
}
