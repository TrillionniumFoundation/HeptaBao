//! Source-side original native plan, original Actor and binary publication.
use super::*;

struct AdmittedSource {
    ready: wire::AdmissionWire,
    ready_bytes: Zeroizing<Vec<u8>>,
    auth: CowOwner<AuthState>,
    clock: RequestClock,
}

fn native_error(_: Response) -> heptabao_ha_service::HaError {
    heptabao_ha_service::HaError::Transport
}

fn reject(
    peer: heptabao_ha_service::AuthenticatedSnapshotPeer<'_>,
    request: &wire::RequestWire,
    metadata: &[u8],
    response: Response,
) -> Result<(), heptabao_ha_service::HaError> {
    let response = if (400..=599).contains(&response.status) { response } else { unavailable() };
    let status = response.status;
    let reply = wire::ReplyData::from_response(response, &request.cluster).map_err(native_error)?;
    let bytes = wire::encode(&wire::RejectionWire {
        nonce: request.nonce, metadata_sha256: wire::digest(metadata), reply,
    }).map_err(native_error)?;
    peer.reject(status, &bytes)
}

impl Service {
    pub(crate) fn serve_native_snapshot_peer(
        service: &Arc<Mutex<Service>>, ingress: crate::ha::SnapshotIngress<'_>,
    ) -> Result<(), heptabao_ha_service::HaError> {
        let cluster = ingress.cluster().to_owned();
        let source = ingress.source();
        let target = ingress.target();
        let mut peer = ingress.into_peer();
        let deadline = peer.deadline();
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(deadline);
        let metadata = Zeroizing::new(peer.metadata().to_vec());
        let mut request: wire::RequestWire = wire::decode(&metadata).map_err(native_error)?;
        let operation = request.operation().map_err(native_error)?;
        if request.cluster != cluster || request.ingress != source || request.leader != target {
            return Err(heptabao_ha_service::HaError::PeerAuthenticationFailed);
        }
        let execution = {
            let mut writer = service.lock_for_request()
                .map_err(|_| heptabao_ha_service::HaError::Transport)?;
            if !writer.native_ha_snapshot_transport_enabled()
                || writer.state.as_ref().is_none_or(|state| state.cluster_id != cluster)
                || writer.ha.as_ref().is_none_or(|ha| !ha.lock_for_request().is_ok_and(|process|
                    process.native_v6_enabled() && process.local_id().ok() == Some(target)
                        && process.enrolled(source) && process.is_leader().unwrap_or(false)))
            {
                drop(writer);
                return reject(peer, &request, &metadata, unavailable());
            }
            // This is the only Actor admission. Native snapshot clocks remain
            // original, and forwarded=true prevents any routing loop.
            writer.begin_snapshot_request_before(ServiceRequest {
                method: &request.method, path: &request.path, namespace: &request.namespace,
                token: &request.token, body: json!({}),
                wrap_ttl_seconds: request.wrap_ttl_seconds, origin_peer: request.origin_peer,
                client_certificates: request.client_certificates.take(),
            }, deadline, true)
        };
        let mut pending = match execution {
            RequestExecution::Complete(response) => return reject(peer, &request, &metadata, response),
            RequestExecution::External(pending) => pending,
        };
        let admitted = {
            let mut writer = service.lock_for_request()
                .map_err(|_| heptabao_ha_service::HaError::Transport)?;
            writer.snapshot_peer_admission(&pending, &request, &metadata, operation)
        };
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(error) => {
                let response = service.lock_for_request()
                    .map_err(|_| heptabao_ha_service::HaError::Transport)?
                    .finish_external_request(*pending, ExternalEffectResult::SnapshotTransfer(Err(error)));
                return reject(peer, &request, &metadata, response);
            }
        };
        let limits = SnapshotBodyLimits::new(match operation {
            wire::Operation::Download => 0,
            wire::Operation::HistoricalRestore => MAX_NATIVE_ARCHIVE,
        }).map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
        let received = peer.accept_body(limits, &admitted.ready_bytes, |mut body| {
            pending.execute_snapshot_transfer(&mut body)
        });
        let (result, file, verified) = match received {
            Ok(((result, file), verified)) => (result, file, Some(verified)),
            Err(_) => (ExternalEffectResult::SnapshotTransfer(Err(
                Response::error(400, "incomplete authenticated snapshot body"),
            )), None, None),
        };
        // BodyComplete only proves the binary reader. An inner native parser
        // error must still take the original failure finalizer, never complete.
        if !matches!(&result, ExternalEffectResult::SnapshotTransfer(Ok(_))) {
            drop(file);
            let response = service.lock_for_request()
                .map_err(|_| heptabao_ha_service::HaError::Transport)?
                .finish_external_request(*pending, result);
            return reject(peer, &request, &metadata, response);
        }
        let prepared_file = match (operation, file) {
            (wire::Operation::Download, Some(file)) => file::SealedSnapshotFile::seal(file).map(Some),
            (wire::Operation::HistoricalRestore, None) => Ok(None),
            _ => Err(unavailable()),
        };
        let mut file = match prepared_file {
            Ok(file) => file,
            Err(error) => {
                let response = service.lock_for_request()
                    .map_err(|_| heptabao_ha_service::HaError::Transport)?
                    .finish_external_request(*pending, ExternalEffectResult::SnapshotTransfer(Err(error)));
                return reject(peer, &request, &metadata, response);
            }
        };
        let verified = verified.ok_or(heptabao_ha_service::HaError::InvalidFrame)?;
        let downloaded = file.as_ref().map_or_else(wire::BodyDescriptor::empty, file::SealedSnapshotFile::descriptor);
        let completion = service.lock_for_request()
            .map_err(|_| heptabao_ha_service::HaError::Transport)?
            .finish_snapshot_peer_request(*pending, result, &admitted, &verified, downloaded);
        let (status, completion) = match completion {
            Ok(value) => value,
            Err(response) => {
                drop(file);
                return reject(peer, &request, &metadata, response);
            }
        };
        let limit = SnapshotBodyLimits::new(downloaded.bytes)
            .map_err(|_| heptabao_ha_service::HaError::InvalidFrame)?;
        let encoded = match file.as_mut() {
            Some(file) => peer.complete(status, &completion, file, limit)?,
            None => peer.complete(status, &completion, &mut io::empty(), limit)?,
        };
        if wire::BodyDescriptor::from_encoded(&encoded, downloaded.role).map_err(native_error)?
                != downloaded
        {
            return Err(heptabao_ha_service::HaError::InvalidFrame);
        }
        Ok(())
    }

    fn snapshot_peer_admission(
        &mut self, pending: &PendingExternalRequest, request: &wire::RequestWire,
        metadata: &[u8], operation: wire::Operation,
    ) -> Result<AdmittedSource, Response> {
        let ExternalEffectPlan::SnapshotTransfer(plan) = &pending.effect else {
            return Err(unavailable());
        };
        if plan.path != request.path || plan.namespace != request.namespace
            || plan.is_download != (operation == wire::Operation::Download)
            || plan.native_ha_pending_restore.is_some() || plan.native_ha_repair.is_some()
        {
            return Err(unavailable());
        }
        self.check_snapshot_peer_original_plan(plan)?;
        let clock = pending.token_clock.ok_or_else(unavailable)?;
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let auth = state.auth.clone();
        let epoch = state.replay_epoch;
        let actor = auth.snapshot_forward_actor(&plan.actor, &plan.namespace, authority_time(clock)?)
            .map_err(|error| Response::error(error.status, &error.message))?;
        let (identity, witness) = fresh_native(
            self, plan.ha.as_ref().ok_or_else(unavailable)?, &auth, &actor, clock, plan.deadline,
        )?;
        if identity != plan.base { return Err(unavailable()); }
        self.check_snapshot_peer_original_plan(plan)?;
        let data = wire::AdmissionData {
            cluster: request.cluster.clone(), ingress: request.ingress, leader: request.leader,
            nonce: request.nonce, metadata_sha256: wire::digest(metadata), operation,
            original_identity: plan.base, original_epoch: epoch,
            original_auth: auth.forward_owner_projection_digest().map_err(|_| unavailable())?,
            source_activation: wire::digest(plan.activation.as_bytes()),
            seal_identity: plan.seal_identity, prefix: witness.completed_prefix(), actor,
        };
        let ready = wire::AdmissionWire::seal(data, source_key(self)?)?;
        let ready_bytes = wire::encode(&ready)?;
        Ok(AdmittedSource { ready, ready_bytes, auth, clock })
    }

    fn finish_snapshot_peer_request(
        &mut self,
        mut pending: PendingExternalRequest,
        result: ExternalEffectResult,
        admitted: &AdmittedSource,
        uploaded: &VerifiedSnapshotBody,
        downloaded: wire::BodyDescriptor,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Response> {
        let headers = pending.quota_response_headers.take();
        let fingerprint = pending.fingerprint.clone();
        let clock = (pending.now, pending.token_clock);
        let _raw_reply_ingress =
            crate::auth::IngressReplyScope::restore(pending.raw_reply_ingress.clone());
        let (plan, result) = match (pending.effect, result) {
            (ExternalEffectPlan::SnapshotTransfer(plan),
                ExternalEffectResult::SnapshotTransfer(result)) => (*plan, result),
            _ => return Err(unavailable()),
        };
        let _deadline = crate::request_deadline::RequestDeadlineScope::enter(plan.deadline);
        // The entire original finalizer, historical/clock receipt and mandatory
        // audit execute before this actual affine plan returns to this caller.
        let (response, plan) =
            self.complete_snapshot_transfer_retained(plan, result, &fingerprint, clock);
        let response = self.finish_rate_limit_quota_headers(
            headers, response, Some((&fingerprint, clock.0)),
        );
        if !matches!(response.status, 200 | 204) {
            return Err(response);
        }
        let original = &admitted.ready.data;
        original_actor(&admitted.auth, &original.actor, admitted.clock, plan.deadline)?;
        if plan.base != original.original_identity || plan.seal_identity != original.seal_identity
            || wire::digest(plan.activation.as_bytes()) != original.source_activation
        {
            return Err(unavailable());
        }
        let terminal = match original.operation {
            wire::Operation::Download => {
                if response.status != 200 || downloaded.role != wire::BodyRole::NativeArchive {
                    return Err(unavailable());
                }
                self.check_snapshot_peer_download_publication(&plan)?;
                wire::TerminalKind::Download { exported_identity: plan.base }
            }
            wire::Operation::HistoricalRestore => {
                if downloaded != wire::BodyDescriptor::empty() { return Err(unavailable()); }
                let (operation, original_identity, restored_identity, restored_epoch) =
                    self.snapshot_peer_historical_publication(
                        &plan, original.original_auth, original.original_epoch,
                    )?;
                wire::TerminalKind::HistoricalRestore {
                    operation, original_identity, original_epoch: original.original_epoch,
                    restored_identity, restored_epoch,
                }
            }
        };
        let upload_role = match original.operation {
            wire::Operation::Download => wire::BodyRole::Empty,
            wire::Operation::HistoricalRestore => wire::BodyRole::NativeArchive,
        };
        let uploaded = wire::BodyDescriptor::from_verified(uploaded, upload_role)?;
        let (identity, witness) = fresh_native(
            self, plan.ha.as_ref().ok_or_else(unavailable)?, &admitted.auth, &original.actor,
            admitted.clock, plan.deadline,
        )?;
        original_actor(&admitted.auth, &original.actor, admitted.clock, plan.deadline)?;
        if !witness.covers_completed_prefix(&original.prefix) || !downloaded.valid() {
            return Err(unavailable());
        }
        let status = response.status;
        let reply = wire::ReplyData::from_response(response, &original.cluster)?;
        let state = self.state.as_ref().ok_or_else(unavailable)?;
        let data = wire::CompletionData {
            admission_sha256: wire::digest(&admitted.ready_bytes),
            request_digest: wire::request_digest(original.metadata_sha256, uploaded)?,
            response_digest: wire::response_digest(&reply, downloaded)?,
            uploaded, downloaded, terminal, terminal_identity: identity,
            terminal_epoch: state.replay_epoch,
            source_activation: wire::digest(self.unseal_nonce.as_bytes()),
            original_auth: original.original_auth,
            owner_projection: self.forward_owner_projection()?,
            prefix: witness.completed_prefix(), floor: state.auth.terminal_token_clock_floor(),
            precise: state.has_token_api_precision_state(),
            audit_sequence: self.audit_sequence, audit_mac: self.audit_previous,
        };
        live(plan.deadline)?;
        let completion = wire::CompletionWire::seal(reply, data, source_key(self)?)?;
        let bytes = wire::encode(&completion)?;
        // Dropping this exact plan releases its Actor and staged source only
        // after MAC publication; no wire data can reconstruct either authority.
        drop(plan);
        Ok((status, bytes))
    }
}
