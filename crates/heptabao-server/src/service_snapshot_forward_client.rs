//! The ingress owns one selected peer and stages all binary response bytes.
use super::*;
use crate::request_deadline::lock_until;

pub(crate) struct SnapshotForwardPlan {
    endpoint: Option<crate::ha::SnapshotEndpoint>,
    request: wire::RequestWire,
    metadata: Zeroizing<Vec<u8>>,
    owner: LocalOwner,
    initial_activation: Zeroizing<String>,
    clock: RequestClock,
    fingerprint: String,
    transport_attempted: bool,
}

/// Constructed only after complete transport, publication, both native delivery
/// gates and the mandatory ingress audit. HTTP cannot construct this capability.
pub(crate) struct CompletedSnapshotForward {
    response: Response,
    file: Option<SnapshotFile>,
}
impl CompletedSnapshotForward {
    pub(crate) fn into_parts(self) -> (Response, Option<SnapshotFile>) {
        (self.response, self.file)
    }
}

struct OriginalCheckpoint {
    admission: wire::AdmissionWire,
    bytes: Zeroizing<Vec<u8>>,
    auth: CowOwner<AuthState>,
}

impl Service {
    pub(in crate::service::snapshot_transfer) fn begin_snapshot_forward(
        &mut self,
        mut request: ServiceRequest<'_>,
        original_deadline: Instant,
    ) -> Result<SnapshotForwardPlan, Response> {
        if !eligible(&request)? || !self.native_ha_snapshot_transport_enabled() {
            erase_json(&mut request.body);
            return Err(unavailable());
        }
        let started = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| unavailable())?;
        let clock = RequestClock::anchored(wall, started).map_err(|_| unavailable())?;
        let fingerprint = self.request_fingerprint(
            request.method,
            request.path,
            request.namespace,
            request.token,
        );
        self.audit_event("request", &fingerprint, wall.as_secs(), None)
            .map_err(|_| unavailable())?;
        let admitted: Result<SnapshotForwardPlan, Response> = (|| {
            let endpoint = self
                .ha
                .as_ref()
                .ok_or_else(unavailable)?
                .lock_for_request()
                .map_err(|_| unavailable())?
                .snapshot_endpoint_before(original_deadline)
                .map_err(|_| unavailable())?;
            let owner = LocalOwner::capture(self, endpoint.deadline())?;
            erase_json(&mut request.body);
            let request = wire::RequestWire {
                version: 1,
                cluster: endpoint.cluster().to_owned(),
                ingress: endpoint.source(),
                leader: endpoint.target(),
                hop: 1,
                nonce: crate::crypto::random::<32>().map_err(|_| unavailable())?,
                method: request.method.to_owned(),
                path: request.path.to_owned(),
                namespace: request.namespace.to_owned(),
                token: request.token.to_owned(),
                wrap_ttl_seconds: request.wrap_ttl_seconds,
                origin_peer: request.origin_peer,
                client_certificates: request.client_certificates.take(),
            };
            request.operation()?;
            let metadata = wire::encode(&request)?;
            Ok(SnapshotForwardPlan {
                endpoint: Some(endpoint),
                request,
                metadata,
                owner,
                clock,
                fingerprint: fingerprint.clone(),
                transport_attempted: false,
                initial_activation: Zeroizing::new(self.unseal_nonce.clone()),
            })
        })();
        match admitted {
            Ok(plan) => Ok(plan),
            Err(mut response) => {
                if self
                    .audit_event(
                        "response",
                        &fingerprint,
                        wall.as_secs(),
                        Some(response.status),
                    )
                    .is_err()
                {
                    erase_json(&mut response.body);
                    self.recovery_required = true;
                    self.ha_activation = None;
                    self.ha_read_cache = None;
                    response = unavailable();
                }
                Err(response)
            }
        }
    }
}

impl SnapshotForwardPlan {
    #[cfg(test)]
    pub(crate) fn fixture_request_context(&self) -> ([u8; 32], Instant) {
        (self.request.nonce, self.owner.deadline)
    }

    fn accept_ready(
        &self,
        service: &mut Service,
        bytes: &[u8],
    ) -> Result<OriginalCheckpoint, Response> {
        self.owner.check(service)?;
        if service.unseal_nonce != *self.initial_activation {
            return Err(unavailable());
        }
        let admission: wire::AdmissionWire = wire::decode(bytes)?;
        admission.verify(&self.request, &self.metadata, self.owner.key(service)?)?;
        if admission.data.seal_identity != self.owner.seal_identity {
            return Err(unavailable());
        }
        // Only native authenticated catch-up can install this source checkpoint.
        // We hold its actual Auth COW before transmitting any archive byte.
        sync_prefix(
            service,
            &self.owner,
            &admission.data,
            &admission.data.prefix,
        )?;
        let auth = service.state.as_ref().ok_or_else(unavailable)?.auth.clone();
        if auth
            .forward_owner_projection_digest()
            .map_err(|_| unavailable())?
            != admission.data.original_auth
            || service.current_state_identity()? != admission.data.original_identity
            || service.state.as_ref().ok_or_else(unavailable)?.replay_epoch
                != admission.data.original_epoch
        {
            return Err(unavailable());
        }
        let (identity, witness) = fresh_native(
            service,
            &self.owner.ha,
            &auth,
            &admission.data.actor,
            self.clock,
            self.owner.deadline,
        )?;
        if identity != admission.data.original_identity
            || !witness.covers_completed_prefix(&admission.data.prefix)
        {
            return Err(unavailable());
        }
        self.owner.check(service)?;
        original_actor(
            &auth,
            &admission.data.actor,
            self.clock,
            self.owner.deadline,
        )?;
        Ok(OriginalCheckpoint {
            admission,
            bytes: Zeroizing::new(bytes.to_vec()),
            auth,
        })
    }

    fn audit_failure(
        &self,
        service: &mut Service,
        mut response: Response,
        authenticated: Option<&wire::CompletionData>,
    ) -> CompletedSnapshotForward {
        let now = self.clock.admitted_at().duration_since_epoch().as_secs();
        if service
            .audit_event("response", &self.fingerprint, now, Some(response.status))
            .is_err()
        {
            erase_json(&mut response.body);
            service.recovery_required = true;
            service.ha_activation = None;
            service.ha_read_cache = None;
            // Never infer a publication or its recovery reference from response JSON.
            // Only authenticated completion data can retain those exact fields.
            response = self.audit_veto_response(authenticated);
        }
        CompletedSnapshotForward {
            response,
            file: None,
        }
    }

    fn audit_veto_response(&self, authenticated: Option<&wire::CompletionData>) -> Response {
        match authenticated {
            Some(data) => self.uncertain_completion(data),
            None if self.transport_attempted => self.uncertain(),
            None => unavailable(),
        }
    }

    fn uncertain(&self) -> Response {
        Response {
            status: 503,
            body: json!({"errors":["native snapshot forwarding outcome requires reconciliation"],
                "outcome_unknown":true,"retry_allowed":false}),
            unwrapped_json: None,
            response_headers: Default::default(),
            consistency_index: None,
        }
    }

    /// Same original HTTP BodyReader, consumed at most once. No remote result
    /// can request replay, leader chase, a new deadline or an HTTP redirect.
    pub(crate) fn execute(
        mut self,
        service: &Arc<Mutex<Service>>,
        upload: &mut impl Read,
    ) -> CompletedSnapshotForward {
        let _scope = crate::request_deadline::RequestDeadlineScope::enter(self.owner.deadline);
        let operation = match self.request.operation() {
            Ok(operation) => operation,
            Err(error) => return self.finish_failure(service, error),
        };
        let upload_limit = match operation {
            wire::Operation::Download => 0,
            wire::Operation::HistoricalRestore => MAX_NATIVE_ARCHIVE,
        };
        let response_limit = match operation {
            wire::Operation::Download => MAX_NATIVE_ARCHIVE,
            wire::Operation::HistoricalRestore => 0,
        };
        let limits = match (
            SnapshotBodyLimits::new(upload_limit),
            SnapshotBodyLimits::new(response_limit),
        ) {
            (Ok(upload), Ok(response)) => (upload, response),
            _ => return self.finish_failure(service, unavailable()),
        };
        let mut file = match self.owner.lease.file(response_limit, self.owner.deadline) {
            Ok(file) => file,
            Err(_) => return self.finish_failure(service, unavailable()),
        };
        let Some(endpoint) = self.endpoint.take() else {
            return self.finish_failure(service, unavailable());
        };
        let mut original = None;
        // This irreversible local marker precedes the single transport call.
        // A failed exchange is never treated as proof that the leader did no work.
        self.transport_attempted = true;
        let exchange = endpoint.exchange(&self.metadata, upload, &mut file, limits, |metadata| {
            let mut writer = lock_until(service, self.owner.deadline)
                .map_err(|_| heptabao_ha_service::HaError::Transport)?;
            let checkpoint = self
                .accept_ready(&mut writer, metadata)
                .map_err(|_| heptabao_ha_service::HaError::PeerAuthenticationFailed)?;
            original = Some(checkpoint);
            Ok(())
        });
        let result = match exchange {
            Ok(result) => result,
            Err(_) => return self.finish_failure(service, self.uncertain()),
        };
        if result.status() >= 400 {
            return self.finish_rejection(service, result);
        }
        let Some(original) = original else {
            return self.finish_failure(service, self.uncertain());
        };
        // Hash/seal only the held private file, outside the Service writer.
        let file = match operation {
            wire::Operation::Download => match file::SealedSnapshotFile::seal(file) {
                Ok(sealed) => Some(sealed),
                Err(_) => return self.finish_failure(service, self.uncertain()),
            },
            wire::Operation::HistoricalRestore => {
                if file.len() != 0 {
                    return self.finish_failure(service, self.uncertain());
                }
                drop(file);
                None
            }
        };
        let completion: Result<CompletedSnapshotForward, Response> = (|| {
            let mut writer = lock_until(service, self.owner.deadline).map_err(|_| unavailable())?;
            self.owner.check(&writer)?;
            let wire: wire::CompletionWire = wire::decode(result.metadata())?;
            if wire.reply.status != result.status() {
                return Err(unavailable());
            }
            let completion = wire.authenticate(
                &original.admission,
                &original.bytes,
                result.request_body().ok_or_else(unavailable)?,
                result.response_body().ok_or_else(unavailable)?,
                self.owner.key(&writer)?,
            )?;
            let (reply, data) = completion.into_parts();
            if file.as_ref().map_or_else(
                wire::BodyDescriptor::empty,
                file::SealedSnapshotFile::descriptor,
            ) != data.downloaded
            {
                drop(file);
                return Ok(self.audit_failure(
                    &mut writer,
                    self.uncertain_completion(&data),
                    Some(&data),
                ));
            }
            let response = match reply.into_response(&self.request.cluster) {
                Ok(response) => response,
                Err(_) => {
                    drop(file);
                    return Ok(self.audit_failure(
                        &mut writer,
                        self.uncertain_completion(&data),
                        Some(&data),
                    ));
                }
            };
            Ok(self.finish_success(&mut writer, original, data, response, file))
        })();
        match completion {
            Ok(reply) => reply,
            Err(_) => self.finish_failure(service, self.uncertain()),
        }
    }

    /// HTTP framing failed before the endpoint could be consumed. This records
    /// the terminal admission error and drops the original owner without I/O.
    pub(crate) fn reject_before_exchange(
        self,
        service: &Arc<Mutex<Service>>,
        response: Response,
    ) -> CompletedSnapshotForward {
        self.finish_failure(service, response)
    }

    fn finish_failure(
        &self,
        service: &Arc<Mutex<Service>>,
        response: Response,
    ) -> CompletedSnapshotForward {
        match lock_until(service, self.owner.deadline) {
            Ok(mut writer) => self.audit_failure(&mut writer, response, None),
            Err(_) => CompletedSnapshotForward {
                response: self.audit_veto_response(None),
                file: None,
            },
        }
    }

    fn finish_rejection(
        &self,
        service: &Arc<Mutex<Service>>,
        result: SnapshotPeerResponse,
    ) -> CompletedSnapshotForward {
        let response = (|| {
            let rejection: wire::RejectionWire = wire::decode(result.metadata())?;
            if rejection.nonce != self.request.nonce
                || rejection.metadata_sha256 != wire::digest(&self.metadata)
                || rejection.reply.status != result.status()
                || !(400..=599).contains(&result.status())
            {
                return Err(unavailable());
            }
            rejection.reply.into_response(&self.request.cluster)
        })()
        .unwrap_or_else(|_| self.uncertain());
        self.finish_failure(service, response)
    }

    fn delivery_check(
        &self,
        service: &mut Service,
        original: &OriginalCheckpoint,
        data: &wire::CompletionData,
        response: &Response,
        activation: &str,
    ) -> Result<(), Response> {
        if wire::observed_response_digest(response, &self.request.cluster, data.downloaded)?
            != data.response_digest
        {
            return Err(unavailable());
        }
        self.owner.check(service)?;
        sync_prefix(service, &self.owner, &original.admission.data, &data.prefix)?;
        let (_, witness) = fresh_native(
            service,
            &self.owner.ha,
            &original.auth,
            &original.admission.data.actor,
            self.clock,
            self.owner.deadline,
        )?;
        let state = service.state.as_ref().ok_or_else(unavailable)?;
        if service.unseal_nonce != activation
            || state.cluster_id != self.request.cluster
            || state.replay_epoch != data.terminal_epoch
            || !witness.covers_completed_prefix(&data.prefix)
            || service.forward_owner_projection()? != data.owner_projection
            || !floor_covers(service, data)
        {
            return Err(unavailable());
        }
        // Historical restore retains the original Auth owner. Download also
        // requires the current owner, so a concurrent revocation is a veto.
        if original.admission.data.operation == wire::Operation::Download {
            original_actor(
                &state.auth,
                &original.admission.data.actor,
                self.clock,
                self.owner.deadline,
            )?;
        }
        original_actor(
            &original.auth,
            &original.admission.data.actor,
            self.clock,
            self.owner.deadline,
        )?;
        self.owner.check(service)
    }

    fn finish_success(
        &self,
        service: &mut Service,
        original: OriginalCheckpoint,
        data: wire::CompletionData,
        mut response: Response,
        file: Option<file::SealedSnapshotFile>,
    ) -> CompletedSnapshotForward {
        let checked = (|| {
            // Only actual authenticated catch-up can create the final capsule.
            // An original Auth view never becomes the newly restored Auth owner.
            sync_prefix(service, &self.owner, &original.admission.data, &data.prefix)?;
            let activation = Zeroizing::new(service.unseal_nonce.clone());
            #[cfg(test)]
            service.fixture_snapshot_forward_fault(
                test_faults::Point::IngressFirstDelivery,
                self.request.nonce,
                self.owner.deadline,
                &original.admission.data,
            );
            self.delivery_check(service, &original, &data, &response, &activation)?;
            Ok::<_, Response>(activation)
        })();
        let activation = match checked {
            Ok(activation) => activation,
            Err(_) => {
                drop(file);
                return self.audit_failure(service, self.uncertain_completion(&data), Some(&data));
            }
        };
        let now = self.clock.admitted_at().duration_since_epoch().as_secs();
        // The source committed the original terminal clock floor. Ingress
        // validates it and performs its mandatory audit, without another use.
        if service
            .audit_event("response", &self.fingerprint, now, Some(response.status))
            .is_err()
        {
            erase_json(&mut response.body);
            drop(file);
            service.recovery_required = true;
            service.ha_activation = None;
            service.ha_read_cache = None;
            return CompletedSnapshotForward {
                response: self.uncertain_completion(&data),
                file: None,
            };
        }
        #[cfg(test)]
        service.fixture_snapshot_forward_fault(
            test_faults::Point::IngressSecondDelivery,
            self.request.nonce,
            self.owner.deadline,
            &original.admission.data,
        );
        if self
            .delivery_check(service, &original, &data, &response, &activation)
            .is_err()
        {
            erase_json(&mut response.body);
            response.response_headers.clear();
            response.consistency_index = None;
            drop(file);
            let error = failed_delivery(
                service,
                &self.fingerprint,
                now,
                self.uncertain_completion(&data),
                || self.uncertain_completion(&data),
            );
            return CompletedSnapshotForward {
                response: error,
                file: None,
            };
        }
        let file = file.map(file::SealedSnapshotFile::into_file);
        CompletedSnapshotForward { response, file }
    }

    fn uncertain_completion(&self, data: &wire::CompletionData) -> Response {
        let mut response = self.uncertain();
        if let wire::TerminalKind::HistoricalRestore { operation, .. } = &data.terminal
            && let Some(body) = response.body.as_object_mut()
        {
            body.insert("root_attempted".into(), Value::Bool(true));
            body.insert(
                "recovery_reference".into(),
                Value::String(format!("native-v6-restore-{}", hex(operation))),
            );
        }
        response
    }
}
