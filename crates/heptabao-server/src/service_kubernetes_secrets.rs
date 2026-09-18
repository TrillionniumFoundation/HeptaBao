//! Service-owned execution boundary for Kubernetes TokenRequest effects.
//!
//! EngineState durably records the issuance intent before this plan is exposed.
//! The external request runs without the global Service writer. A transport or
//! response failure is outcome-unknown: the intent remains and automatic retry
//! is forbidden because Kubernetes may already have minted a valid token.

use super::*;
use crate::engines::kubernetes::{TokenMetadata, TokenRequestPlan};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub(crate) struct KubernetesTokenEffectPlan {
    pub inner: TokenRequestPlan,
    outbound: crate::outbound::Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    now: u64,
}

impl KubernetesTokenEffectPlan {
    pub(crate) fn new(
        inner: TokenRequestPlan,
        outbound: crate::outbound::Outbound,
        ha: Option<Arc<Mutex<HaProcess>>>,
        now: u64,
    ) -> Self {
        Self {
            inner,
            outbound,
            ha,
            now,
        }
    }

    pub(crate) fn execute(&self) -> Result<TokenMetadata, Response> {
        if let Some(ha) = &self.ha {
            ha.lock()
                .map_err(|_| failure("Kubernetes provider HA fence unavailable"))?
                .ensure_linearizable()
                .map_err(|_| failure("Kubernetes provider HA fence unavailable"))?;
        }
        let mut spec = serde_json::Map::new();
        spec.insert("expirationSeconds".into(), json!(self.inner.ttl));
        if !self.inner.audiences.is_empty() {
            spec.insert("audiences".into(), json!(self.inner.audiences));
        }
        let request = json!({
            "apiVersion":"authentication.k8s.io/v1",
            "kind":"TokenRequest",
            "spec":Value::Object(spec)
        });
        let value = self
            .outbound
            .post_json_bearer(
                &self.inner.provider_url,
                self.inner.provider_token.expose(),
                &request,
            )
            .map_err(|_| outcome_unknown(&self.inner.lease_id))?;
        token_metadata(&value, &self.inner, self.now)
    }
}

fn outcome_unknown(lease_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":["Kubernetes TokenRequest outcome indeterminate; durable intent retained"],
            "lease_id":lease_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}

fn failure(message: &str) -> Response {
    Response::error(503, message)
}

fn token_metadata(
    value: &Value,
    plan: &TokenRequestPlan,
    now: u64,
) -> Result<TokenMetadata, Response> {
    let status = value
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(|| outcome_unknown(&plan.lease_id))?;
    let token = status
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| outcome_unknown(&plan.lease_id))?;
    if token.is_empty()
        || token.len() > 64 * 1024
        || !token.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let mut pieces = token.split('.');
    let Some(_header) = pieces.next() else {
        return Err(outcome_unknown(&plan.lease_id));
    };
    let Some(payload) = pieces.next() else {
        return Err(outcome_unknown(&plan.lease_id));
    };
    let Some(_signature) = pieces.next() else {
        return Err(outcome_unknown(&plan.lease_id));
    };
    if pieces.next().is_some() || payload.len() > 32 * 1024 {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| outcome_unknown(&plan.lease_id))?,
    );
    let claims = crate::auth::parse_strict_json(&decoded)
        .map_err(|_| outcome_unknown(&plan.lease_id))?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| outcome_unknown(&plan.lease_id))?;
    let maximum_expiry = now
        .checked_add(plan.ttl)
        .and_then(|value| value.checked_add(120))
        .ok_or_else(|| outcome_unknown(&plan.lease_id))?;
    if expires_at <= now || expires_at > maximum_expiry {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let expected_subject = format!(
        "system:serviceaccount:{}:{}",
        plan.kubernetes_namespace, plan.service_account_name
    );
    if claims.get("sub").and_then(Value::as_str) != Some(expected_subject.as_str()) {
        return Err(outcome_unknown(&plan.lease_id));
    }
    let audiences = observed_audiences(&claims, &plan.lease_id)?;
    if !plan
        .audiences
        .iter()
        .all(|audience| audiences.iter().any(|observed| observed == audience))
    {
        return Err(outcome_unknown(&plan.lease_id));
    }
    Ok(TokenMetadata {
        token: Zeroizing::new(token.to_owned()),
        expires_at,
        audiences,
    })
}

fn observed_audiences(value: &Value, lease_id: &str) -> Result<Vec<String>, Response> {
    let Some(audience) = value.get("aud") else {
        return Ok(Vec::new());
    };
    let values = if let Some(text) = audience.as_str() {
        vec![text.to_owned()]
    } else {
        audience
            .as_array()
            .ok_or_else(|| outcome_unknown(lease_id))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| outcome_unknown(lease_id))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    if values.len() > 16
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 256
                || !value.is_ascii()
                || value.bytes().any(|byte| byte < 32 || byte == 127)
        })
    {
        return Err(outcome_unknown(lease_id));
    }
    Ok(values)
}

impl Service {
    pub(super) fn kubernetes_secret_handles(
        state: &State,
        namespace: &str,
        path: &str,
    ) -> bool {
        state.engines.kubernetes_mount(namespace, path).is_some()
    }

    pub(super) fn kubernetes_secret_route(
        &mut self,
        mut state: State,
        principal: Option<&Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = state
            .engines
            .required_capability(request.namespace, request.method, request.path)
            .unwrap_or("update");
        if let Err(error) = state.auth.authorize_request(
            principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        let Some(mount) = state
            .engines
            .kubernetes_mount(request.namespace, request.path)
        else {
            return Response::error(404, "Kubernetes mount not found");
        };
        let relative = request.path.strip_prefix(&mount).unwrap_or_default();
        if relative == "config" && matches!(request.method, "POST" | "PUT") {
            let Some(host) = request.body.get("kubernetes_host").and_then(Value::as_str) else {
                return Response::error(400, "kubernetes_host is required");
            };
            let probe = format!("{host}/api/");
            if self.outbound.endpoint(&probe, "https").is_err() {
                return Response::error(
                    400,
                    "Kubernetes origin/path is not enrolled by trusted process configuration",
                );
            }
        }
        let dispatch = match state.engines.kubernetes_dispatch(
            request.namespace,
            request.path,
            request.method,
            request.body,
            request.now,
        ) {
            Ok(Some(value)) => value,
            Ok(None) => return Response::error(404, "Kubernetes mount not found"),
            Err(error) => return Response::error(error.status, &error.message),
        };
        match dispatch {
            crate::engines::kubernetes::Dispatch::Immediate(mut response) => {
                if response.mutated {
                    state.schema = CURRENT_STATE_SCHEMA;
                    if let Err(error) = state.validate_format() {
                        return error;
                    }
                    if let Err(error) = self.commit_state(&state) {
                        return error;
                    }
                    self.state = Some(state);
                }
                Response {
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                }
            }
            crate::engines::kubernetes::Dispatch::External(plan) => {
                state.schema = CURRENT_STATE_SCHEMA;
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                self.state = Some(state);
                self.pending_kubernetes_token = Some(KubernetesTokenEffectPlan::new(
                    plan,
                    self.outbound.clone(),
                    self.ha.clone(),
                    request.now,
                ));
                Response::error(500, "Kubernetes TokenRequest was not dispatched")
            }
        }
    }

    pub(super) fn finalize_kubernetes_token(
        &mut self,
        plan: &KubernetesTokenEffectPlan,
        result: Result<TokenMetadata, Response>,
    ) -> Response {
        let metadata = match result {
            Ok(metadata) => metadata,
            Err(error) => return error,
        };
        if let Some(ha) = &self.ha
            && ha
                .lock()
                .map_err(|_| failure("Kubernetes provider finalize fence unavailable"))
                .and_then(|ha| {
                    ha.ensure_linearizable()
                        .map_err(|_| failure("Kubernetes provider finalize fence unavailable"))
                })
                .is_err()
        {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        let Some(mut state) = self.state.clone() else {
            return post_provider_completion_failure(&plan.inner.lease_id);
        };
        let mut response = match state.engines.kubernetes_finalize(
            &plan.inner.namespace,
            &plan.inner.mount,
            &plan.inner,
            metadata,
        ) {
            Ok(response) => response,
            Err(_) => return post_provider_completion_failure(&plan.inner.lease_id),
        };
        state.schema = CURRENT_STATE_SCHEMA;
        if state.validate_format().is_err() || self.commit_state(&state).is_err() {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        self.state = Some(state);
        Response {
            status: response.status,
            body: std::mem::take(&mut response.body),
        }
    }
}

fn post_provider_completion_failure(lease_id: &str) -> Response {
    Response {
        status: 503,
        body: json!({
            "errors":["Kubernetes token was observed but local completion was not established; durable intent retained"],
            "lease_id":lease_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}
