//! The real Service owns online authentication, live identity projection and
//! durable publication. Neither TokenReview nor an ID token is a Principal.
use super::*;
use crate::auth::{
    AuthError, KubernetesLoginObservation, KubernetesLoginPlan, LdapLoginObservation,
    LdapLoginPlan, OidcBeginObservation, OidcBeginPlan, OidcExchange, OidcLoginObservation,
    ProviderRenewalObservation, ProviderRenewalPlan, RadiusLoginObservation, RadiusLoginPlan,
    RemoteJwtLoginObservation, RemoteJwtLoginPlan,
};

fn consumed_oidc_error(mut response: Response) -> Response {
    // The upstream code may already have been spent even when live local
    // identity policy rejects the resulting login. Never invite callback retry.
    if let Some(body) = response.body.as_object_mut() {
        body.insert("retry_allowed".into(), json!(false));
        body.insert("start_new_login".into(), json!(true));
        body.insert("oidc_session_consumed".into(), json!(true));
    }
    response
}

fn auth_error(error: AuthError) -> Response {
    Response::error(error.status, &error.message)
}

pub(super) enum OnlineAuthEffect {
    RemoteJwt(RemoteJwtLoginPlan),
    Kubernetes(KubernetesLoginPlan),
    Ldap(LdapLoginPlan),
    Radius(RadiusLoginPlan),
    ProviderRenewal(Box<ProviderRenewalEffect>),
    OidcBegin(OidcBeginPlan),
    OidcCallback {
        namespace: String,
        mount: String,
        exchange: OidcExchange,
        now: u64,
        started: std::time::Instant,
    },
}

pub(super) struct ProviderRenewalEffect {
    plan: ProviderRenewalPlan,
    actor: Principal,
    echo_token: Option<Zeroizing<String>>,
    path: String,
    wrap_ttl_seconds: Option<u64>,
}

pub(super) struct OnlineAuthEffectPlan {
    outbound: crate::outbound::Outbound,
    activation_nonce: String,
    namespace: String,
    request_now: u64,
    effect: OnlineAuthEffect,
}

pub(crate) enum OnlineAuthObservation {
    RemoteJwt(RemoteJwtLoginObservation),
    Kubernetes(KubernetesLoginObservation),
    Ldap(LdapLoginObservation),
    Radius(RadiusLoginObservation),
    ProviderRenewal(ProviderRenewalObservation),
    OidcBegin(OidcBeginObservation),
    OidcCallback(OidcLoginObservation),
}

impl OnlineAuthEffectPlan {
    pub(super) fn execute(&self) -> Result<OnlineAuthObservation, Response> {
        match &self.effect {
            OnlineAuthEffect::RemoteJwt(plan) => plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::RemoteJwt)
                .map_err(auth_error),
            OnlineAuthEffect::Kubernetes(plan) => plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::Kubernetes)
                .map_err(auth_error),
            OnlineAuthEffect::Ldap(plan) => plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::Ldap)
                .map_err(auth_error),
            OnlineAuthEffect::Radius(plan) => plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::Radius)
                .map_err(auth_error),
            OnlineAuthEffect::ProviderRenewal(plan) => plan
                .plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::ProviderRenewal)
                .map_err(auth_error),
            OnlineAuthEffect::OidcBegin(plan) => plan
                .execute(&self.outbound)
                .map(OnlineAuthObservation::OidcBegin)
                .map_err(auth_error),
            OnlineAuthEffect::OidcCallback {
                namespace,
                exchange,
                now,
                started,
                ..
            } => exchange
                .execute(namespace, *now, *started, &self.outbound)
                .map(OnlineAuthObservation::OidcCallback)
                .map_err(|error| consumed_oidc_error(auth_error(error))),
        }
    }

    fn callback(&self) -> bool {
        matches!(&self.effect, OnlineAuthEffect::OidcCallback { .. })
    }
}

impl Service {
    pub(super) fn online_provider_renewal(
        &mut self,
        admitted: &State,
        principal: &mut Option<Principal>,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let plan = match admitted.auth.prepare_provider_renewal(
            principal.as_ref(),
            request.namespace,
            request.method,
            request.path,
            request.body,
            request.now,
        ) {
            Ok(None) => return None,
            Err(error) => return Some(auth_error(error)),
            Ok(Some(plan)) => plan,
        };
        if self.pending_online_auth_effect.is_some() {
            return Some(Response::error(
                503,
                "online authentication dispatch state is unavailable",
            ));
        }
        let Some(actor) = principal.take() else {
            return Some(Response::error(403, "missing client token"));
        };
        self.pending_online_auth_effect = Some(OnlineAuthEffectPlan {
            outbound: self.outbound.clone(),
            activation_nonce: self.unseal_nonce.clone(),
            namespace: request.namespace.to_owned(),
            request_now: request.now,
            effect: OnlineAuthEffect::ProviderRenewal(Box::new(ProviderRenewalEffect {
                plan,
                actor,
                echo_token: match request.path {
                    "auth/token/renew-self" => Some(Zeroizing::new(request.token.to_owned())),
                    "auth/token/renew" => request
                        .body
                        .get("token")
                        .and_then(Value::as_str)
                        .map(|token| Zeroizing::new(token.to_owned())),
                    _ => None,
                },
                path: request.path.to_owned(),
                wrap_ttl_seconds: request.wrap_ttl_seconds,
            })),
        });
        Some(Response::error(
            500,
            "provider renewal provider effect was not dispatched",
        ))
    }

    fn finalize_provider_renewal_effect(
        &mut self,
        namespace: &str,
        renewal: ProviderRenewalEffect,
        observation: ProviderRenewalObservation,
    ) -> Response {
        let ProviderRenewalEffect {
            plan,
            mut actor,
            echo_token,
            path,
            wrap_ttl_seconds,
        } = renewal;
        let Some(mut state) = self.state.clone() else {
            return Response::error(503, "provider renewal authority is unavailable");
        };
        let now = plan.observed_now();
        if let Err(error) = Self::bind_identity_principal(&state, &mut actor, namespace) {
            return error;
        }
        let mut response = match state
            .auth
            .finish_provider_renewal(plan, &actor, observation, now)
        {
            Ok(response) => response,
            Err(error) => return auth_error(error),
        };
        if let Err(error) = Self::finish_identity_response(
            &mut state.auth,
            &mut state.engines,
            &mut response,
            namespace,
            now,
        ) {
            erase_json(&mut response.body);
            return error;
        }
        // Echo only an already-supplied bearer; accessor renewal never
        // reconstructs one. Wrapping and renewal publish in one transaction.
        if let Some(token) = echo_token {
            response.body["auth"]["client_token"] = json!(token.as_str());
        }
        if let Some(ttl) = wrap_ttl_seconds {
            let wrapped = state
                .auth
                .wrap_response(namespace, &path, ttl, &response.body, now);
            erase_json(&mut response.body);
            response = match wrapped {
                Ok(response) => response,
                Err(error) => return auth_error(error),
            };
        }
        state.schema = CURRENT_STATE_SCHEMA;
        if let Err(error) = self.commit_state(&state) {
            erase_json(&mut response.body);
            return error;
        }
        self.state = Some(state);
        Response {
            status: response.status,
            body: response.body,
        }
    }

    pub(super) fn online_login(
        &mut self,
        admitted: &State,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        // Remote-JWT login is a normal auth route, but its discovery/JWKS read
        // must not hold the Service writer. Wrapped JWT login keeps the legacy
        // path until wrapping and split-phase publication share one envelope.
        if request.wrap_ttl_seconds.is_none() {
            match admitted.auth.prepare_remote_jwt_login(
                request.namespace,
                request.path,
                request.method,
                request.body,
                request.now,
            ) {
                Ok(Some(plan)) => {
                    if self.pending_online_auth_effect.is_some() {
                        return Some(Response::error(
                            503,
                            "online authentication dispatch state is unavailable",
                        ));
                    }
                    self.pending_online_auth_effect = Some(OnlineAuthEffectPlan {
                        outbound: self.outbound.clone(),
                        activation_nonce: self.unseal_nonce.clone(),
                        namespace: request.namespace.into(),
                        request_now: request.now,
                        effect: OnlineAuthEffect::RemoteJwt(plan),
                    });
                    return Some(Response::error(
                        500,
                        "remote JWT refresh was not dispatched",
                    ));
                }
                Err(error) => return Some(auth_error(error)),
                Ok(None) => {}
            }
        }

        let (kind, mount, suffix) = admitted
            .auth
            .online_mount_route(request.namespace, request.path)?;
        let handled = kind == "kubernetes" && suffix == "login"
            || kind == "ldap" && suffix.starts_with("login/")
            || kind == "radius" && suffix == "login"
            || kind == "oidc" && matches!(suffix.as_str(), "oidc/auth_url" | "oidc/callback");
        if !handled {
            return None;
        }
        if !matches!(request.method, "POST" | "PUT") {
            return Some(Response::error(405, "online login requires POST or PUT"));
        }
        if request.wrap_ttl_seconds.is_some() {
            return Some(Response::error(
                400,
                "online login wrapping is not supported",
            ));
        }
        if self.pending_online_auth_effect.is_some() {
            return Some(Response::error(
                503,
                "online authentication dispatch state is unavailable",
            ));
        }

        let effect = if kind == "kubernetes" {
            match admitted.auth.prepare_kubernetes_login(
                request.namespace,
                &mount,
                request.body,
                request.now,
            ) {
                Ok(plan) => OnlineAuthEffect::Kubernetes(plan),
                Err(error) => return Some(auth_error(error)),
            }
        } else if kind == "ldap" {
            let Some(name) = suffix.strip_prefix("login/") else {
                return Some(Response::error(404, "unsupported LDAP login route"));
            };
            match admitted.auth.prepare_ldap_login(
                request.namespace,
                &mount,
                name,
                request.method,
                request.body,
                request.now,
            ) {
                Ok(plan) => OnlineAuthEffect::Ldap(plan),
                Err(error) => return Some(auth_error(error)),
            }
        } else if kind == "radius" {
            match admitted.auth.prepare_radius_login(
                request.namespace,
                &mount,
                request.method,
                request.body,
                request.now,
            ) {
                Ok(plan) => OnlineAuthEffect::Radius(plan),
                Err(error) => return Some(auth_error(error)),
            }
        } else if suffix == "oidc/auth_url" {
            match admitted.auth.prepare_oidc_begin(
                request.namespace,
                &mount,
                request.body,
                request.now,
            ) {
                Ok(plan) => OnlineAuthEffect::OidcBegin(plan),
                Err(error) => return Some(auth_error(error)),
            }
        } else {
            let entered = std::time::Instant::now();
            let mut state = admitted.clone();
            let exchange =
                match state
                    .auth
                    .consume_oidc(request.namespace, &mount, request.body, request.now)
                {
                    Ok(exchange) => exchange,
                    Err(error) => return Some(auth_error(error)),
                };
            state.schema = CURRENT_STATE_SCHEMA;
            // Critical order: one-use session removal is replicated and durable
            // before the global Service writer is released for code exchange.
            if let Err(error) = self.commit_state(&state) {
                return Some(error);
            }
            self.state = Some(state);
            let Some(exchange) = exchange else {
                return Some(consumed_oidc_error(Response::error(
                    403,
                    "expired OIDC session consumed",
                )));
            };
            OnlineAuthEffect::OidcCallback {
                namespace: request.namespace.into(),
                mount,
                exchange,
                now: request.now,
                started: entered,
            }
        };

        self.pending_online_auth_effect = Some(OnlineAuthEffectPlan {
            outbound: self.outbound.clone(),
            activation_nonce: self.unseal_nonce.clone(),
            namespace: request.namespace.into(),
            request_now: request.now,
            effect,
        });
        // The request wrapper consumes the pending plan before a response can
        // leave Service. Direct callers execute it synchronously; HTTP releases
        // the Service writer first.
        Some(Response::error(
            500,
            "online authentication external effect was not dispatched",
        ))
    }

    fn revalidate_online_authority(
        &mut self,
        namespace: &str,
        activation_nonce: &str,
    ) -> Result<(), Response> {
        if self.recovery_required || self.state.is_none() || self.unseal_nonce != activation_nonce {
            return Err(Response::error(
                503,
                "online authentication authority changed",
            ));
        }
        if let Some(ha) = self.ha.as_ref() {
            match ha.lock() {
                Ok(ha) if ha.is_leader().unwrap_or(false) => {}
                _ => return Err(Response::error(503, "online authentication leader changed")),
            }
        }
        self.sync_from_ha()?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "online authentication authority unavailable"))?;
        if !state.namespace_exists(namespace) || state.namespace_is_sealed(namespace) {
            return Err(Response::error(
                503,
                "online authentication namespace unavailable",
            ));
        }
        Ok(())
    }

    pub(super) fn finalize_online_auth_effect(
        &mut self,
        plan: OnlineAuthEffectPlan,
        result: Result<OnlineAuthObservation, Response>,
    ) -> Response {
        let callback = plan.callback();
        let request_namespace = plan.namespace.clone();
        let request_now = plan.request_now;
        let observation = match result {
            Ok(observation) => observation,
            Err(response) => return response,
        };
        if let Err(response) =
            self.revalidate_online_authority(&request_namespace, &plan.activation_nonce)
        {
            return if callback {
                consumed_oidc_error(response)
            } else {
                response
            };
        }
        if let OnlineAuthEffect::ProviderRenewal(renewal) = plan.effect {
            let OnlineAuthObservation::ProviderRenewal(observation) = observation else {
                return Response::error(503, "provider renewal observation type mismatch");
            };
            return self.finalize_provider_renewal_effect(
                &request_namespace,
                *renewal,
                observation,
            );
        }
        let Some(mut state) = self.state.clone() else {
            let response = Response::error(503, "server sealed after online authentication entry");
            return if callback {
                consumed_oidc_error(response)
            } else {
                response
            };
        };

        let issued = match (plan.effect, observation) {
            (
                OnlineAuthEffect::RemoteJwt(auth_plan),
                OnlineAuthObservation::RemoteJwt(observed),
            ) => state.auth.finish_remote_jwt_login(auth_plan, observed),
            (
                OnlineAuthEffect::Kubernetes(auth_plan),
                OnlineAuthObservation::Kubernetes(observed),
            ) => state.auth.finish_kubernetes_login(auth_plan, observed),
            (OnlineAuthEffect::Ldap(auth_plan), OnlineAuthObservation::Ldap(observed)) => {
                state.auth.finish_ldap_login(auth_plan, observed)
            }
            (OnlineAuthEffect::Radius(auth_plan), OnlineAuthObservation::Radius(observed)) => {
                state.auth.finish_radius_login(auth_plan, observed)
            }
            (
                OnlineAuthEffect::OidcBegin(auth_plan),
                OnlineAuthObservation::OidcBegin(observed),
            ) => state.auth.finish_oidc_begin(auth_plan, observed),
            (
                OnlineAuthEffect::OidcCallback {
                    namespace,
                    mount,
                    exchange,
                    ..
                },
                OnlineAuthObservation::OidcCallback(observed),
            ) => state
                .auth
                .finish_oidc_observation(&namespace, &mount, exchange, observed),
            _ => {
                self.recovery_required = true;
                return Response::error(503, "online authentication observation type mismatch");
            }
        };

        let mut issued = match issued {
            Ok(issued) => issued,
            Err(error) => {
                let response = auth_error(error);
                return if callback {
                    consumed_oidc_error(response)
                } else {
                    response
                };
            }
        };
        if let Err(error) = Self::finish_identity_response(
            &mut state.auth,
            &mut state.engines,
            &mut issued,
            &request_namespace,
            request_now,
        ) {
            erase_json(&mut issued.body);
            return if callback {
                consumed_oidc_error(error)
            } else {
                error
            };
        }
        state.schema = CURRENT_STATE_SCHEMA;
        if let Err(error) = self.commit_state(&state) {
            erase_json(&mut issued.body);
            if callback {
                return consumed_oidc_error(Response {
                    status: 503,
                    body: json!({
                        "errors":["OIDC session consumed; token publication failed"],
                        "retry_allowed":false,
                        "start_new_login":true,
                        "recovery_required":self.recovery_required
                    }),
                });
            }
            return error;
        }
        self.state = Some(state);
        Response {
            status: issued.status,
            body: issued.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Root, bootstrap, call};
    use super::*;
    fn prepared(root: &Root) -> Result<(Service, String, Value), Box<dyn std::error::Error>> {
        let mut service = root.service()?;
        let (key, _) = bootstrap(&mut service)?;
        let (auth, _, callback) = AuthState::oidc_test_fixture();
        let mut state = service.state.as_ref().ok_or("missing state")?.clone();
        state.auth = auth.into();
        state.validate_format().map_err(|_| "invalid test state")?;
        service
            .commit_state(&state)
            .map_err(|_| "test state did not persist")?;
        service.state = Some(state);
        Ok((service, key, callback))
    }
    fn sessions(service: &Service) -> Result<usize, Box<dyn std::error::Error>> {
        let auth = serde_json::to_value(&service.state.as_ref().ok_or("missing state")?.auth)?;
        Ok(auth["oidc_mounts"][""]["browser"]["sessions"]
            .as_object()
            .ok_or("missing sessions")?
            .len())
    }
    #[test]
    fn oidc_service_commits_consumption_before_failed_egress_and_reopen_rejects_replay()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let (mut service, key, body) = prepared(&root)?;
        let generation = service.durable.as_ref().ok_or("no durable")?.generation();
        let response = service.handle_at(
            "POST",
            "auth/browser/oidc/callback",
            "",
            "",
            body.clone(),
            110,
        );
        assert_eq!(response.status, 503); // no host-enrolled network; not a fake successful exchange
        assert_eq!(response.body["retry_allowed"], false);
        assert_eq!(sessions(&service)?, 0);
        assert_eq!(
            service.durable.as_ref().ok_or("no durable")?.generation(),
            generation + 1
        );
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 111)
                .status,
            403
        );
        Ok(())
    }
    #[test]
    fn oidc_service_pre_entry_capacity_refusal_preserves_session_without_code_exchange()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let (mut service, _, body) = prepared(&root)?;
        let generation = service.durable.as_ref().ok_or("no durable")?.generation();
        service.state_capacity = 1;
        let response = service.handle_at(
            "POST",
            "auth/browser/oidc/callback",
            "",
            "",
            body.clone(),
            110,
        );
        assert_eq!(response.status, 507); // exchange first would instead return 503
        assert_eq!(sessions(&service)?, 1);
        assert_eq!(
            service.durable.as_ref().ok_or("no durable")?.generation(),
            generation
        );
        service.state_capacity = MAX_STATE_BYTES;
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 111)
                .status,
            503
        );
        assert_eq!(sessions(&service)?, 0);
        Ok(())
    }
    #[test]
    fn oidc_service_observed_expiry_is_durable_even_on_denial()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let (mut service, key, body) = prepared(&root)?;
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/browser/oidc/callback",
                    "",
                    "",
                    body.clone(),
                    400
                )
                .status,
            403
        );
        assert_eq!(sessions(&service)?, 0);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 300)
                .status,
            403
        );
        Ok(())
    }
    #[test]
    fn oidc_service_request_audit_failure_preserves_session_and_result_failure_never_refunds_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let (mut service, _, body) = prepared(&root)?;
        service.audit_capacity = service.audit.metadata()?.len();
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 110)
                .status,
            503
        );
        assert_eq!(sessions(&service)?, 1);
        let root = Root::new();
        let (mut service, key, body) = prepared(&root)?;
        let event = AuditUnsigned {
            schema: 2,
            sequence: service.audit_sequence + 1,
            previous: STANDARD.encode(service.audit_previous),
            time: 110,
            kind: "request".into(),
            path_digest: service.request_fingerprint("POST", "auth/browser/oidc/callback", "", ""),
            status: None,
        };
        let payload = serde_json::to_vec(&event)?;
        let mac = STANDARD.encode(hmac::sign(&service.audit_key, &payload).as_ref());
        let next = serde_json::to_vec(&AuditRecord { event, mac })?.len() + 1;
        service.audit_capacity = service.audit.metadata()?.len() + next as u64;
        assert_eq!(
            service
                .handle_at(
                    "POST",
                    "auth/browser/oidc/callback",
                    "",
                    "",
                    body.clone(),
                    110
                )
                .status,
            503
        );
        assert!(service.recovery_required);
        assert_eq!(sessions(&service)?, 0);
        drop(service);
        let mut service = root.service()?;
        assert_eq!(
            call(&mut service, "POST", "sys/unseal", "", json!({"key":key})).status,
            200
        );
        assert_eq!(
            service
                .handle_at("POST", "auth/browser/oidc/callback", "", "", body, 111)
                .status,
            403
        );
        Ok(())
    }
    #[test]
    fn online_auth_state_cannot_hide_in_schema_four_or_an_unknown_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root::new();
        let (service, _, _) = prepared(&root)?;
        let mut state = service.state.as_ref().ok_or("missing state")?.clone();
        state.schema = 4;
        assert!(state.validate_format().is_err());
        state.schema = CURRENT_STATE_SCHEMA;
        assert!(state.validate_format().is_ok());
        state.schema = CURRENT_STATE_SCHEMA + 1;
        assert!(state.validate_format().is_err());
        let (auth, _) = AuthState::bootstrap(100)?;
        state.auth = auth.into();
        state.schema = 4;
        assert!(state.validate_format().is_ok());
        let encoded = serde_json::to_string(&state)?;
        assert!(!encoded.contains("oidc_mounts") && !encoded.contains("kubernetes_mounts"));
        Ok(())
    }
    #[test]
    fn consumed_oidc_identity_denial_keeps_status_and_explicit_no_retry() {
        for status in [400, 403, 503] {
            let response = consumed_oidc_error(Response::error(status, "fixed login failure"));
            assert_eq!(response.status, status);
            assert_eq!(response.body["retry_allowed"], false);
            assert_eq!(response.body["start_new_login"], true);
            assert_eq!(response.body["oidc_session_consumed"], true);
            assert!(response.body.get("auth").is_none());
        }
    }
}
