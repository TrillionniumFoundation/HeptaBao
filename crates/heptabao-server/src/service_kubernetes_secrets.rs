//! Service-owned execution boundary for Kubernetes TokenRequest effects.
//!
//! EngineState durably records the issuance intent before this plan is exposed.
//! The external request runs without the global Service writer. A transport or
//! response failure is outcome-unknown: the intent remains and automatic retry
//! is forbidden because Kubernetes may already have minted a valid token.

use super::*;
use crate::engines::kubernetes::{TokenMetadata, TokenRequestPlan};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;
#[path = "service_kubernetes_artifact.rs"]
mod artifact;

pub(crate) struct KubernetesTokenEffectPlan {
    pub inner: TokenRequestPlan,
    outbound: crate::outbound::Outbound,
    ha: Option<Arc<Mutex<HaProcess>>>,
    now: u64,
    started: std::time::Instant,
    token_clock: Option<RequestClock>,
    activation_nonce: String,
    last_use: bool,
    // Process-local affine admission; never persisted or reconstructed on replay.
    response_authority: Option<Box<plugin::PluginResponseAuthority>>,
    // Exact original routing and publication, never response JSON metadata.
    request_path: Option<String>,
    mount_binding: Option<(u64, u64)>,
    deadline: Option<std::time::Instant>,
    committed_receipt: Option<crate::engines::KubernetesDeliveryReceipt>,
    audited_fingerprint: Option<String>,
}

impl KubernetesTokenEffectPlan {
    pub(crate) fn new(
        inner: TokenRequestPlan,
        outbound: crate::outbound::Outbound,
        ha: Option<Arc<Mutex<HaProcess>>>,
        now: u64,
        started: std::time::Instant,
        activation_nonce: String,
        last_use: bool,
    ) -> Self {
        Self {
            inner,
            outbound,
            ha,
            now,
            started,
            token_clock: None,
            activation_nonce,
            last_use,
            response_authority: None,
            request_path: None,
            mount_binding: None,
            deadline: crate::request_deadline::current(),
            committed_receipt: None,
            audited_fingerprint: None,
        }
    }

    pub(super) fn mark_response_audited(&mut self, fingerprint: &str) {
        self.audited_fingerprint = Some(fingerprint.to_owned());
    }

    fn completed_time(&self) -> Result<AuthorityTime, Response> {
        match self.token_clock {
            Some(clock) => clock
                .with_seconds_floor(self.now)
                .and_then(RequestClock::observed_at)
                .map(AuthorityTime::Precise)
                .map_err(|_| failure("trusted token clock is unavailable")),
            None => Ok(AuthorityTime::Coarse(self.completed_now())),
        }
    }

    fn completed_now(&self) -> u64 {
        self.completed_at(std::time::Instant::now())
    }

    fn completed_at(&self, observed: std::time::Instant) -> u64 {
        std::time::Duration::from_secs(self.now)
            .saturating_add(observed.saturating_duration_since(self.started))
            .as_secs()
    }

    pub(crate) fn execute(&self) -> Result<TokenMetadata, Response> {
        if let Some(ha) = &self.ha {
            ha.lock_for_request()
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
        consistency_index: None,
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
    if plan.artifact_contract.is_some() {
        return artifact::metadata(value, plan);
    }
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
    let claims =
        crate::auth::parse_strict_json(&decoded).map_err(|_| outcome_unknown(&plan.lease_id))?;
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
        artifact_lifetime_nanos: None,
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
    pub(super) fn kubernetes_secret_handles(state: &State, namespace: &str, path: &str) -> bool {
        state.engines.kubernetes_mount(namespace, path).is_some()
    }

    pub(super) fn kubernetes_secret_route(
        &mut self,
        mut state: State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let capability = state
            .engines
            .required_capability(request.namespace, request.method, request.path)
            .unwrap_or("update");
        let time = match request.token_time() {
            Ok(time) => state.auth.token_api_observed_time(time),
            Err(error) => return error,
        };
        let time = match state.engines.kubernetes_artifact_time(time) {
            Ok(time) => time,
            Err(error) => return Response::error(error.status, &error.message),
        };
        if let Err(error) = state.auth.authorize_request_observed(
            &principal,
            request.namespace,
            request.path,
            capability,
            time,
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
        let issuer = if relative.starts_with("creds/") {
            match state.auth.admitted_kubernetes_lease_issuer_observed(
                &principal,
                request.namespace,
                time,
            ) {
                Ok(owner) => {
                    if owner.entity_id.as_deref().is_some_and(|id| {
                        !state
                            .engines
                            .identity_projection(request.namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    }) {
                        return Response::error(
                            403,
                            "Kubernetes lease owner identity is unavailable",
                        );
                    }
                    Some(owner)
                }
                Err(error) => return Response::error(error.status, &error.message),
            }
        } else {
            None
        };
        let dispatch = match state.engines.kubernetes_dispatch_observed(
            request.namespace,
            request.path,
            request.method,
            request.body,
            (request.now, time),
            issuer.as_ref(),
        ) {
            Ok(Some(value)) => value,
            Ok(None) => return Response::error(404, "Kubernetes mount not found"),
            Err(error) => return Response::error(error.status, &error.message),
        };
        match dispatch {
            crate::engines::kubernetes::Dispatch::Immediate(mut response) => {
                if response.mutated {
                    state.schema = state.writer_schema();
                    if let Err(error) = state.validate_format() {
                        return error;
                    }
                    if let Err(error) = self.commit_state(&state) {
                        return error;
                    }
                    self.state = Some(state);
                }
                Response {
                    consistency_index: None,
                    status: response.status,
                    body: std::mem::take(&mut response.body),
                }
            }
            crate::engines::kubernetes::Dispatch::External(mut plan) => {
                if crate::engines::kubernetes_artifact::ISSUANCE_ENABLED {
                    let defaults = match state.auth.secret_lease_defaults() {
                        Ok(defaults) => defaults,
                        Err(error) => return Response::error(error.status, &error.message),
                    };
                    if let Err(error) = state
                        .engines
                        .bind_kubernetes_opaque_artifact_intent(&mut plan, defaults)
                    {
                        return Response::error(error.status, &error.message);
                    }
                    if let Err(error) = state.engines.observe_kubernetes_artifact_time(time) {
                        return Response::error(error.status, &error.message);
                    }
                    state.schema = state.writer_schema();
                }
                let plan = *plan;
                state.schema = state.writer_schema();
                if let Err(error) = state.validate_format() {
                    return error;
                }
                if let Err(error) = self.commit_state(&state) {
                    return error;
                }
                let last_use = principal.consumed_last_use();
                let authority = plugin::PluginResponseAuthority::new(
                    principal,
                    &state,
                    request,
                    capability,
                    false,
                    &self.unseal_nonce,
                )
                .with_time_floor(state.engines.lease_clock());
                self.state = Some(state);
                let mut effect = KubernetesTokenEffectPlan::new(
                    plan,
                    self.outbound.clone(),
                    self.ha.clone(),
                    request.now,
                    request.admission_started,
                    self.unseal_nonce.clone(),
                    last_use,
                );
                effect.token_clock = request.token_clock;
                effect.request_path = Some(request.path.to_owned());
                effect.mount_binding = self.state.as_ref().and_then(|state| {
                    state
                        .engines
                        .kubernetes_mount_binding(request.namespace, request.path)
                });
                effect.response_authority = Some(Box::new(authority));
                self.pending_kubernetes_token = Some(effect);
                Response::error(500, "Kubernetes TokenRequest was not dispatched")
            }
        }
    }

    pub(super) fn finalize_kubernetes_token(
        &mut self,
        plan: &mut KubernetesTokenEffectPlan,
        result: Result<TokenMetadata, Response>,
    ) -> Response {
        if plan.mount_binding.is_none() || plan.request_path.is_none() {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        let mut authority = plan.response_authority.take();
        let mut receipt = None;
        let response = self.finalize_kubernetes_token_checked(
            plan,
            result,
            || plan.completed_time(),
            |service| {
                let authority = authority
                    .as_mut()
                    .ok_or_else(|| post_provider_completion_failure(&plan.inner.lease_id))?;
                service.validate_plugin_response(authority)
            },
            &mut receipt,
        );
        // Return the same Box, including the admitted Principal and clock, on
        // success and error. It remains alive through the outer audit/stamp.
        plan.response_authority = authority;
        plan.committed_receipt = receipt;
        response
    }

    // Test seam for provider/owner semantics, not a product delivery entry point.
    #[cfg(test)]
    fn finalize_kubernetes_token_with_clock(
        &mut self,
        plan: &KubernetesTokenEffectPlan,
        result: Result<TokenMetadata, Response>,
        mut completed_now: impl FnMut() -> u64,
    ) -> Response {
        let mut receipt = None;
        self.finalize_kubernetes_token_checked(
            plan,
            result,
            || Ok(AuthorityTime::Coarse(completed_now())),
            |_| Ok(()),
            &mut receipt,
        )
    }

    fn finalize_kubernetes_token_checked(
        &mut self,
        plan: &KubernetesTokenEffectPlan,
        result: Result<TokenMetadata, Response>,
        mut completed_time: impl FnMut() -> Result<AuthorityTime, Response>,
        mut authorize_delivery: impl FnMut(&mut Self) -> Result<(), Response>,
        committed_receipt: &mut Option<crate::engines::KubernetesDeliveryReceipt>,
    ) -> Response {
        let metadata = match result {
            Ok(metadata) => metadata,
            Err(error) => return error,
        };
        // Install the latest HA application graph, not only its ReadIndex.
        // A restore/reseal invalidates the observation even if config is equal.
        if self
            .revalidate_online_authority_with_sync(
                &plan.inner.namespace,
                &plan.activation_nonce,
                |service| service.sync_from_ha_with_anchor(false),
            )
            .is_err()
        {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        if plan
            .mount_binding
            .zip(plan.request_path.as_deref())
            .is_some_and(|(binding, path)| {
                self.state.as_ref().is_none_or(|state| {
                    state
                        .engines
                        .kubernetes_mount(&plan.inner.namespace, path)
                        .as_deref()
                        != Some(plan.inner.mount.as_str())
                        || state
                            .engines
                            .kubernetes_mount_binding(&plan.inner.namespace, path)
                            != Some(binding)
                })
            })
        {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        let delivery_allowed = authorize_delivery(self).is_ok();
        let Some(mut state) = self.state.clone() else {
            return post_provider_completion_failure(&plan.inner.lease_id);
        };
        let time = match completed_time().and_then(|time| {
            time.with_seconds_floor(state.engines.lease_clock())
                .map_err(|_| failure("trusted token clock is unavailable"))
        }) {
            Ok(time) => match state
                .engines
                .kubernetes_artifact_time(state.auth.token_api_observed_time(time))
            {
                Ok(time) => time,
                Err(_) => return post_provider_completion_failure(&plan.inner.lease_id),
            },
            Err(_) => return post_provider_completion_failure(&plan.inner.lease_id),
        };
        if state.auth.observe_token_api_time(time).is_err() {
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        let now = time.seconds();
        let live = delivery_allowed && Self::kubernetes_completion_owner_live(&state, plan, time);
        let mut response = match state.engines.kubernetes_finalize_observed(
            &plan.inner.namespace,
            &plan.inner.mount,
            &plan.inner,
            metadata,
            time,
            live,
        ) {
            Ok(response) => response,
            Err(_) => return post_provider_completion_failure(&plan.inner.lease_id),
        };
        state.schema = state.writer_schema();
        if state.validate_format().is_err() || self.commit_state(&state).is_err() {
            erase_json(&mut response.body);
            return post_provider_completion_failure(&plan.inner.lease_id);
        }
        self.state = Some(state);
        // Read only the actual lease graph after successful durable commit.
        // This typed observation cannot be populated by a public 200/body.
        *committed_receipt = match self.state.as_ref().and_then(|state| {
            state
                .engines
                .capture_kubernetes_delivery_receipt(&plan.inner)
                .ok()
        }) {
            Some(receipt) => receipt,
            None => {
                erase_json(&mut response.body);
                return post_provider_completion_failure(&plan.inner.lease_id);
            }
        };
        if plan.last_use && response.body["local_lease_retired"] == true {
            return Response::error(
                400,
                "Secret cannot be returned; token had one use left, so leased credentials were immediately revoked.",
            );
        }
        if response.status == 200 {
            let delivery_allowed = authorize_delivery(self).is_ok();
            // Revalidation can synchronize HA; sample time after it completes.
            let Some(current) = self.state.as_ref() else {
                erase_json(&mut response.body);
                return post_provider_completion_failure(&plan.inner.lease_id);
            };
            let time = match completed_time().and_then(|time| {
                time.with_seconds_floor(now)
                    .map_err(|_| failure("trusted token clock is unavailable"))
            }) {
                Ok(time) => current.auth.token_api_observed_time(time),
                Err(_) => {
                    erase_json(&mut response.body);
                    return post_provider_completion_failure(&plan.inner.lease_id);
                }
            };
            let now = time.seconds();
            // Persisted provider expiry may be shorter than the admitted cap.
            let remaining = committed_receipt
                .as_ref()
                .map_or(0, |receipt| receipt.expires_at().saturating_sub(now));
            if !delivery_allowed
                || !Self::kubernetes_completion_owner_live(current, plan, time)
                || remaining == 0
            {
                erase_json(&mut response.body);
                let mut retired = current.clone();
                if retired.auth.observe_token_api_time(time).is_err() {
                    return post_provider_completion_failure(&plan.inner.lease_id);
                }
                if retired
                    .engines
                    .kubernetes_retire_lease(
                        &plan.inner.namespace,
                        &plan.inner.mount,
                        &plan.inner.lease_id,
                    )
                    .is_err()
                    || retired.validate_format().is_err()
                    || self.commit_state(&retired).is_err()
                {
                    return post_provider_completion_failure(&plan.inner.lease_id);
                }
                self.state = Some(retired);
                *committed_receipt = None;
                return retired_kubernetes_response(&plan.inner.lease_id);
            }
            response.body["lease_duration"] = json!(
                committed_receipt
                    .as_ref()
                    .map_or(0, |receipt| receipt.response_lease_duration(now))
            );
        }
        Response {
            consistency_index: None,
            status: response.status,
            body: std::mem::take(&mut response.body),
        }
    }

    /// Keep the original Box and its admitted Principal through actual durable
    /// publication, mandatory response audit and consistency stamping. Neither
    /// the public response body nor a bearer replay creates a receipt.
    pub(super) fn complete_kubernetes_token_delivery(
        &mut self,
        plan: &mut KubernetesTokenEffectPlan,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        if !(200..300).contains(&response.status) {
            return response;
        }
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let checked =
            (|| {
                if plan.audited_fingerprint.as_deref() != Some(fingerprint)
                    || plan
                        .deadline
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                {
                    return Err(failure(
                        "Kubernetes delivery audit or deadline proof is unavailable",
                    ));
                }
                let authority = plan.response_authority.as_mut().ok_or_else(|| {
                    failure("Kubernetes original delivery authority is unavailable")
                })?;
                self.validate_plugin_response(authority)?;
                // This may observe a durable floor, but grants no new authority.
                // Recheck the same Box after a real publication can consume time.
                self.persist_terminal_token_clock(plan.token_clock, plan.now)?;
                self.validate_plugin_response(authority)?;
                let state = self
                    .state
                    .as_ref()
                    .ok_or_else(|| failure("Kubernetes delivery is sealed"))?;
                let time = state
                    .engines
                    .kubernetes_artifact_time(
                        state.auth.token_api_observed_time(authority.token_time()?),
                    )
                    .map_err(|error| Response::error(error.status, &error.message))?;
                if !Self::kubernetes_completion_owner_live(state, plan, time) {
                    return Err(failure(
                        "Kubernetes committed lease no longer authorizes credential delivery",
                    ));
                }
                let receipt = plan.committed_receipt.as_ref().ok_or_else(|| {
                    failure("Kubernetes committed delivery receipt is unavailable")
                })?;
                let path = plan
                    .request_path
                    .as_deref()
                    .ok_or_else(|| failure("Kubernetes admitted routing is unavailable"))?;
                let binding = plan
                    .mount_binding
                    .ok_or_else(|| failure("Kubernetes admitted mount owner is unavailable"))?;
                let remaining = state
                    .engines
                    .validate_kubernetes_delivery_receipt_observed(
                        &plan.inner,
                        path,
                        binding,
                        receipt,
                        time,
                    )
                    .map_err(|error| Response::error(error.status, &error.message))?;
                if (remaining == 0 && plan.inner.artifact_contract.is_none())
                    || plan
                        .deadline
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                {
                    return Err(failure(
                        "Kubernetes committed lease no longer authorizes credential delivery",
                    ));
                }
                Ok(remaining)
            })();
        match checked {
            Ok(remaining) => {
                // Only the real persisted lease determines this projection.
                response.body["lease_duration"] = json!(remaining);
                response
            }
            Err(error) => {
                erase_json(&mut response.body);
                response.consistency_index = None;
                // A failed clock can label only this negative observation. It
                // cannot grant delivery, start a new clock or retry TokenRequest.
                let observed = plan
                    .completed_time()
                    .map_or(plan.now, AuthorityTime::seconds);
                if self
                    .audit_event(
                        "kubernetes-delivery-veto",
                        fingerprint,
                        observed,
                        Some(error.status),
                    )
                    .is_err()
                {
                    crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                    self.recovery_required = true;
                    self.ha_activation = None;
                    return failure(
                        "Kubernetes delivery veto audit failed; authoritative recovery required",
                    );
                }
                error
            }
        }
    }

    fn kubernetes_completion_owner_live(
        state: &State,
        plan: &KubernetesTokenEffectPlan,
        time: AuthorityTime,
    ) -> bool {
        let time = state.auth.token_api_observed_time(time);
        plan.inner.authority.expires_at > time.seconds()
            && state.namespace_exists(&plan.inner.namespace)
            && !state.namespace_is_sealed(&plan.inner.namespace)
            && state
                .auth
                .resolve_lease_owner_observed(
                    &plan.inner.authority.owner,
                    &plan.inner.namespace,
                    time,
                )
                .is_some_and(|owner| {
                    // A provider credential cannot outlive the authenticated
                    // exact owner cap, including any service-token ancestor.
                    owner.precise_expires_at.is_none_or(|expires| {
                        time.exact().is_some_and(|observed| observed < expires)
                    }) && owner.entity_id.as_deref().is_none_or(|id| {
                        state
                            .engines
                            .identity_projection(&plan.inner.namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
    }
}

fn post_provider_completion_failure(lease_id: &str) -> Response {
    Response {
        consistency_index: None,
        status: 503,
        body: json!({
            "errors":["Kubernetes token was observed but local lease completion was not established; durable reconciliation state retained"],
            "lease_id":lease_id,
            "reconcile_required":true,
            "retry_allowed":false
        }),
    }
}

fn retired_kubernetes_response(lease_id: &str) -> Response {
    Response {
        consistency_index: None,
        status: 503,
        body: json!({
            "errors":["Kubernetes token observed after lease authority expired or was revoked; credential withheld"],
            "lease_id":lease_id, "retry_allowed":false,
            "provider_token_revoked":false, "local_lease_retired":true
        }),
    }
}

#[cfg(test)]
#[path = "service_kubernetes_lease_tests.rs"]
mod lease_tests;

#[cfg(test)]
#[path = "service_kubernetes_delivery_tests.rs"]
mod delivery_tests;
