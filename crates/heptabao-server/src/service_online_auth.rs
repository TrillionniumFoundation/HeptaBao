//! The real Service owns online authentication, live identity projection and
//! durable publication. Neither TokenReview nor an ID token is a Principal.
use super::*;
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
impl Service {
    pub(super) fn online_login(
        &mut self,
        admitted: &State,
        request: &RequestView<'_>,
    ) -> Option<Response> {
        let (kind, mount, suffix) = admitted
            .auth
            .online_mount_route(request.namespace, request.path)?;
        let handled = kind == "kubernetes" && suffix == "login"
            || kind == "oidc" && matches!(suffix.as_str(), "oidc/auth_url" | "oidc/callback");
        if !handled {
            return None;
        }
        if !matches!(request.method, "POST" | "PUT") {
            return Some(Response::error(405, "online login requires POST or PUT"));
        }
        // Code exchange consumes an upstream capability. Until wrapping is
        // explicitly reconciled with that two-commit boundary, reject BEFORE
        // consuming a session or contacting the provider.
        if request.wrap_ttl_seconds.is_some() {
            return Some(Response::error(
                400,
                "online login wrapping is not supported",
            ));
        }
        let entered = std::time::Instant::now();
        let mut state = admitted.clone();
        let callback = kind == "oidc" && suffix == "oidc/callback";
        let issued = if kind == "kubernetes" {
            state.auth.kubernetes_login(
                request.namespace,
                &mount,
                request.body,
                request.now,
                &self.outbound,
            )
        } else if suffix == "oidc/auth_url" {
            state.auth.begin_oidc(
                request.namespace,
                &mount,
                request.body,
                request.now,
                &self.outbound,
            )
        } else {
            let exchange =
                match state
                    .auth
                    .consume_oidc(request.namespace, &mount, request.body, request.now)
                {
                    Ok(exchange) => exchange,
                    Err(error) => return Some(Response::error(error.status, &error.message)),
                };
            state.schema = CURRENT_STATE_SCHEMA;
            // Critical order: one-use session removal must be replicated and
            // durable before even the first byte of the code exchange.
            if let Err(error) = self.commit_state(&state) {
                return Some(error);
            }
            self.state = Some(state.clone());
            let Some(exchange) = exchange else {
                return Some(consumed_oidc_error(Response::error(
                    403,
                    "expired OIDC session consumed",
                )));
            };
            state.auth.finish_oidc(
                request.namespace,
                &mount,
                exchange,
                request.now,
                entered,
                &self.outbound,
            )
        };
        Some(match issued {
            Ok(mut issued) => {
                if let Err(error) = Self::finish_identity_response(
                    &mut state.auth,
                    &mut state.engines,
                    &mut issued,
                    request.namespace,
                    request.now,
                ) {
                    erase_json(&mut issued.body);
                    return Some(if callback {
                        consumed_oidc_error(error)
                    } else {
                        error
                    });
                }
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = self.commit_state(&state) {
                    erase_json(&mut issued.body);
                    if callback {
                        return Some(consumed_oidc_error(Response {
                            status: 503,
                            body: json!({"errors":["OIDC session consumed; token publication failed"],
                            "retry_allowed":false,"start_new_login":true,"recovery_required":self.recovery_required}),
                        }));
                    }
                    return Some(error);
                }
                self.state = Some(state);
                Response {
                    status: issued.status,
                    body: issued.body,
                }
            }
            Err(error) if callback => {
                consumed_oidc_error(Response::error(error.status, &error.message))
            }
            Err(error) => Response::error(error.status, &error.message),
        })
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
        state.auth = auth;
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
        state.auth = auth;
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
