//! Private EAB administration retains the admitted affine Vault actor through
//! publication, audit and delivery. Public HMAC account proofs have no actor.
use super::pki_acme::Authority;
use super::*;
use crate::auth::Timestamp;

impl Service {
    pub(super) fn pki_eab_handles(&self, state: &State, request: &RequestView<'_>) -> bool {
        state
            .engines
            .acme_view(
                request.namespace,
                request.path,
                &state.cluster_id,
                state.namespaces.incarnation(request.namespace),
            )
            .ok()
            .flatten()
            .is_some_and(|view| {
                view.endpoint == "new-eab"
                    || view.endpoint == "eab"
                    || view.endpoint.starts_with("eab/")
            })
    }
    pub(super) fn pki_eab_route(
        &mut self,
        mut candidate: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = match request.method {
            "POST" | "PUT" => "update",
            "LIST" => "list",
            "DELETE" => "delete",
            _ => return Response::error(405, "unsupported operation"),
        };
        let at = match request
            .token_time()
            .map(|time| candidate.auth.token_api_observed_time(time))
        {
            Ok(time) => match time
                .exact()
                .or_else(|| Timestamp::whole(time.seconds()).ok())
            {
                Some(at) => candidate.engines.acme_observed_time(at),
                None => return Response::error(503, "EAB original clock unavailable"),
            },
            Err(error) => return error,
        };
        // Copy only the existing ingress clock with the admitted durable floor.
        // This keeps its original Instant/wall anchor, rather than sampling anew.
        let scoped = RequestView {
            method: request.method,
            path: request.path,
            namespace: request.namespace,
            token: request.token,
            body: request.body,
            now: request.now.max(at.seconds()),
            admission_started: request.admission_started,
            token_clock: request
                .token_clock
                .map(|clock| clock.with_timestamp_floor(at)),
            allow_forward: request.allow_forward,
            enforce_namespace: request.enforce_namespace,
            wrap_ttl_seconds: request.wrap_ttl_seconds,
            origin_peer: request.origin_peer,
            client_certificates: request.client_certificates,
        };
        let view = match candidate.engines.acme_view(
            scoped.namespace,
            scoped.path,
            &candidate.cluster_id,
            candidate.namespaces.incarnation(scoped.namespace),
        ) {
            Ok(Some(view)) => view,
            Ok(None) => return Response::error(404, "no handler for route"),
            Err(error) => return Response::from_engine_error(error),
        };
        let identity = match self.current_state_identity() {
            Ok(identity) => identity,
            Err(error) => return error,
        };
        let operator = plugin::PluginResponseAuthority::new(
            principal,
            &candidate,
            &scoped,
            capability,
            false,
            &self.unseal_nonce,
        );
        let mut authority =
            Authority::capture(&candidate, &view, &scoped, &self.unseal_nonce, None)
                .with_operator(operator);
        if let Err(error) = authority.check(self) {
            return error;
        }
        let time = match authority.observe_operator(&mut candidate) {
            Ok(time) => time,
            Err(error) => return error,
        };
        let at = match time
            .exact()
            .or_else(|| Timestamp::whole(time.seconds()).ok())
        {
            Some(at) => candidate.engines.acme_observed_time(at),
            None => return Response::error(503, "EAB original time unavailable"),
        };
        let payload =
            match candidate
                .engines
                .acme_eab_request(&view, scoped.method, scoped.body, at)
            {
                Ok(value) => value,
                Err(error) if error.status == 404 && error.message == "no value found" => {
                    return Response {
                        status: 404,
                        body: json!({"errors":[]}),
                        response_headers: Default::default(),
                        consistency_index: None,
                    };
                }
                Err(error) => return Response::from_engine_error(error),
            };
        let mut response = Response::ok(payload);
        let mut wrapper = None;
        if let Some(ttl) = scoped.wrap_ttl_seconds.filter(|ttl| *ttl != 0) {
            // EAB and its one-use wrapper share this candidate and the original
            // admitted operator. The wrapper never creates a new caller or clock.
            let time = match authority.observe_operator(&mut candidate) {
                Ok(time) => time,
                Err(error) => {
                    erase_json(&mut response.body);
                    return error;
                }
            };
            let mut wrapped = match candidate.auth.wrap_response(
                scoped.namespace,
                scoped.path,
                ttl,
                &response.body,
                time.seconds(),
            ) {
                Ok(wrapped) => wrapped,
                Err(error) => {
                    erase_json(&mut response.body);
                    return Response::error(error.status, &error.message);
                }
            };
            let Some(bearer) = wrapped.body["wrap_info"]["token"].as_str() else {
                erase_json(&mut response.body);
                erase_json(&mut wrapped.body);
                return Response::error(503, "EAB wrapper did not retain its private bearer");
            };
            wrapper = Some(zeroize::Zeroizing::new(bearer.to_owned()));
            erase_json(&mut response.body);
            response.status = wrapped.status;
            response.body = std::mem::take(&mut wrapped.body);
        }
        let publication = (|| -> Result<(), Response> {
            authority.check(self)?;
            if self.current_state_identity()? != identity {
                return Err(Response::error(
                    503,
                    "EAB transaction changed before publication",
                ));
            }
            candidate.schema = candidate.writer_schema();
            if candidate.engines.record_root().is_none() {
                if self.record_root.is_some() {
                    return Err(Response::error(
                        503,
                        "EAB cannot downgrade authenticated record root",
                    ));
                }
                let key = crypto::random::<32>().map_err(|e| Response::error(503, e))?;
                candidate.engines = candidate
                    .engines
                    .migrate_kv1_records(crate::state_records::AddressKey::from_bytes(key))
                    .map_err(Response::from_engine_error)?
                    .into();
            }
            let plan = self.prepare_record_plan(&mut candidate)?;
            if let Some(bearer) = wrapper.take() {
                authority.bind_operator_wrapper(bearer);
            }
            authority.bind_candidate(&candidate)?;
            self.commit_record_plan_with_before_publish(
                &candidate,
                plan,
                |auth| {
                    authority.check_state(&candidate)?;
                    authority.validate_operator_auth(auth)
                },
                #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
                None,
            )?;
            candidate = self.install_committed_namespace_view(candidate.clone());
            authority.bind_candidate(&candidate)?;
            Ok(())
        })();
        if let Err(error) = publication {
            erase_json(&mut response.body);
            return error;
        }
        self.state = Some(candidate);
        self.pending_acme_authority = Some(authority);
        response
    }
}
