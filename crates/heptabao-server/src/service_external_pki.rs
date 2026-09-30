//! Direct external PKI generation on the audited Service effect boundary.
//! Metadata and signing use one immutable deployment-enrolled provider route.
//! Whole-state fencing intentionally rejects even unrelated concurrent writes.
use super::plugin::{KmsKeyBinding, PluginResponseAuthority, SharedKmsPlugin};
use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;
use heptabao_domain::SecretValue;
use heptabao_kms_contracts::KmsCapability;
use heptabao_plugin_host::PluginHostState;
use std::sync::Arc;
use zeroize::Zeroizing;

pub(super) struct ExternalPkiPlan {
    request: SecretValue,
    template: crate::engines::ExternalPkiTemplate,
    namespace: String,
    mount: String,
    mount_incarnation: u64,
    sign_url: String,
    metadata_url: String,
    outbound: crate::outbound::Outbound,
    provider_binding: Option<(SharedKmsPlugin, KmsKeyBinding, u64)>,
    expected_identity: crate::state_record_root::StateIdentity,
    expected_generation: plugin::PublicationGeneration,
    authority: PluginResponseAuthority,
    deadline: Option<std::time::Instant>,
}

struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}

pub(crate) struct Observation {
    material: crate::engines::ExternalPkiMaterial,
    signature: Zeroizing<Vec<u8>>,
}

fn unknown() -> Response {
    Response::error(
        503,
        "external PKI unknown after entry: provider readback required; no blind retry",
    )
}

fn crypto_response(
    response: crate::outbound::ExternalTransitResponse,
) -> Result<SensitiveJson, Response> {
    match response {
        crate::outbound::ExternalTransitResponse::Crypto(value) => Ok(SensitiveJson(value)),
        crate::outbound::ExternalTransitResponse::Rejected => Err(Response::error(
            500,
            "external PKI provider rejected generation",
        )),
    }
}

impl ExternalPkiPlan {
    fn provider_host_current(&self) -> bool {
        self.provider_binding
            .as_ref()
            .is_none_or(|(host, binding, generation)| {
                host.try_lock().is_ok_and(|guard| {
                    binding.enabled
                        && binding.capabilities.contains(&KmsCapability::Sign)
                        && guard.state() == PluginHostState::Active
                        && guard.manifest().descriptor().generation() == *generation
                })
            })
    }

    pub(super) fn execute(&self) -> Result<Observation, Response> {
        let _deadline_scope = self
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if self.authority.deadline_expired() {
            return Err(Response::error(
                503,
                "external PKI rejected before entry: deadline",
            ));
        }
        if !self.provider_host_current() {
            return Err(Response::error(
                503,
                "external PKI rejected before entry: provider host authority changed",
            ));
        }
        let envelope = SensitiveJson(
            crate::auth::parse_strict_json(self.request.expose()).map_err(|_| unknown())?,
        );
        let token = envelope.0["token"].as_str().ok_or_else(unknown)?;
        let namespace = envelope.0["namespace"].as_str().ok_or_else(unknown)?;
        let version = envelope.0["remote_version"].as_u64().ok_or_else(unknown)?;
        let metadata = crypto_response(
            self.outbound
                .get_external_transit(&self.metadata_url, token, namespace)
                .map_err(|message| Response::error(503, message))?,
        )?;
        let data = metadata
            .0
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(unknown)?;
        if data.get("type").and_then(Value::as_str) != Some("ed25519") {
            return Err(Response::error(
                501,
                "external PKI requires a qualified Ed25519 public-key lane",
            ));
        }
        if data.get("supports_signing").and_then(Value::as_bool) != Some(true)
            || data.get("latest_version").and_then(Value::as_u64).is_none()
        {
            return Err(unknown());
        }
        // Pinned 2.7 direct generation rejects an old fixed mapping after the
        // provider rotates; it does not silently bind a fresh issuer to latest.
        if data.get("latest_version").and_then(Value::as_u64) != Some(version) {
            return Err(Response::error(
                400,
                "external PKI direct generation provider version changed",
            ));
        }
        let version_key = version.to_string();
        let public_text = data
            .get("keys")
            .and_then(Value::as_object)
            .and_then(|keys| keys.get(&version_key))
            .and_then(|key| key.get("public_key"))
            .and_then(Value::as_str)
            .ok_or_else(unknown)?;
        if public_text.len() > 64 {
            return Err(unknown());
        }
        let public = BASE64.decode(public_text).map_err(|_| unknown())?;
        if public.len() != 32 || BASE64.encode(&public) != public_text {
            return Err(unknown());
        }
        let public: [u8; 32] = public.try_into().map_err(|_| unknown())?;
        let material = self
            .template
            .clone()
            .materialize(public)
            .map_err(|cause| Response::error(cause.status, &cause.message))?;
        // Check again between the public metadata read and the sign effect.
        // The original admission deadline is retained throughout both calls.
        if self.authority.deadline_expired() || !self.provider_host_current() {
            return Err(Response::error(
                503,
                "external PKI withheld after metadata: deadline or host authority changed; no blind retry",
            ));
        }
        let body = SensitiveJson(
            json!({"input":BASE64.encode(&material.tbs),"key_version":version_key,
            "prehashed":false,"signature_algorithm":"pkcs1v15"}),
        );
        let signed = crypto_response(
            self.outbound
                .put_external_transit(&self.sign_url, token, namespace, &body.0)
                .map_err(|message| Response::error(503, message))?,
        )?;
        let data = signed
            .0
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(unknown)?;
        if data
            .keys()
            .any(|field| !matches!(field.as_str(), "signature" | "key_version"))
            || data
                .get("key_version")
                .is_some_and(|value| value.as_u64() != Some(version))
        {
            return Err(unknown());
        }
        let prefix = format!("vault:v{version}:");
        let text = data
            .get("signature")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix(&prefix))
            .ok_or_else(unknown)?;
        if text.len() != 88 {
            return Err(unknown());
        }
        let signature = Zeroizing::new(BASE64.decode(text).map_err(|_| unknown())?);
        if BASE64.encode(&*signature) != text {
            return Err(unknown());
        }
        material
            .verify(&signature)
            .map_err(|cause| Response::error(cause.status, &cause.message))?;
        Ok(Observation {
            material,
            signature,
        })
    }
}

impl Service {
    pub(super) fn stage_external_pki(
        &mut self,
        state: &State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let Some(capability) =
            state
                .engines
                .required_capability(request.namespace, request.method, request.path)
        else {
            return Response::error(404, "PKI route not found");
        };
        if let Err(cause) = state.auth.authorize_request(
            &principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Response::error(cause.status, &cause.message);
        }
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "external PKI response wrapping is not implemented");
        }
        if self.pending_external_pki.is_some() {
            return Response::error(503, "another external PKI generation is pending");
        }
        let plan = match state.engines.prepare_external_pki(
            request.namespace,
            request.method,
            request.path,
            request.body,
            request.now,
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) => return Response::error(404, "external PKI route not found"),
            Err(cause) => return Response::error(cause.status, &cause.message),
        };
        let envelope = match crate::auth::parse_strict_json(plan.request.expose()) {
            Ok(value) => SensitiveJson(value),
            Err(_) => return unknown(),
        };
        let Some(sign_url) = envelope.0["url"].as_str() else {
            return unknown();
        };
        let Some((origin, key)) = sign_url.rsplit_once("/sign/") else {
            return unknown();
        };
        let metadata_url = format!("{origin}/keys/{key}");
        if self.outbound.endpoint(sign_url, "https").is_err()
            || self.outbound.endpoint(&metadata_url, "https").is_err()
        {
            return Response::error(
                503,
                "external PKI rejected before entry: HTTPS route is not deployment-enrolled",
            );
        }
        let provider_binding = match (
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
        ) {
            (Some(host), Some(binding)) => {
                if !binding.enabled || !binding.capabilities.contains(&KmsCapability::Sign) {
                    return Response::error(
                        403,
                        "external PKI provider is disabled or lacks signing capability",
                    );
                }
                let Ok(guard) = host.try_lock() else {
                    return Response::error(503, "external PKI provider host busy");
                };
                if guard.state() != PluginHostState::Active {
                    return Response::error(
                        503,
                        "external PKI provider host revoked or requires reconciliation",
                    );
                }
                let generation = guard.manifest().descriptor().generation();
                Some((Arc::clone(host), binding.clone(), generation))
            }
            (None, None) => None,
            _ => return Response::error(503, "external PKI provider binding is incomplete"),
        };
        let expected_identity = match self.current_state_identity() {
            Ok(value) => value,
            Err(cause) => return cause,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(value) => value,
            Err(cause) => return cause,
        };
        self.pending_external_pki = Some(ExternalPkiPlan {
            request: plan.request,
            template: plan.template,
            namespace: request.namespace.into(),
            mount: plan.mount,
            mount_incarnation: plan.mount_incarnation,
            sign_url: sign_url.into(),
            metadata_url,
            outbound: self.outbound.clone(),
            provider_binding,
            expected_identity,
            expected_generation,
            authority: PluginResponseAuthority::new(
                principal,
                state,
                request,
                capability,
                false,
                &self.unseal_nonce,
            ),
            deadline: crate::request_deadline::current(),
        });
        Response::error(500, "external PKI generation was not dispatched")
    }

    pub(super) fn finalize_external_pki(
        &mut self,
        mut plan: ExternalPkiPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let observation = match result {
            Ok(value) => value,
            Err(cause) => return cause,
        };
        if let Err(cause) = self.validate_plugin_response(&mut plan.authority) {
            return cause;
        }
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let retained_host = plan
            .provider_binding
            .as_ref()
            .map(|(host, _, _)| Arc::clone(host));
        let host_guard = if let Some(host) = retained_host.as_ref() {
            match host.try_lock() {
                Ok(guard) => Some(guard),
                Err(_) => {
                    return Response::error(
                        503,
                        "external PKI provider host busy before publication",
                    );
                }
            }
        } else {
            None
        };
        let provider_current = match (
            &plan.provider_binding,
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
            host_guard.as_ref(),
        ) {
            (None, None, None, None) => true,
            (
                Some((host, binding, generation)),
                Some(current_host),
                Some(current_binding),
                Some(guard),
            ) => {
                Arc::ptr_eq(host, current_host)
                    && binding.enabled
                    && current_binding.enabled
                    && binding.key_id == current_binding.key_id
                    && binding.key_version == current_binding.key_version
                    && binding.capabilities == current_binding.capabilities
                    && guard.state() == PluginHostState::Active
                    && guard.manifest().descriptor().generation() == *generation
            }
            _ => false,
        };
        if !provider_current
            || !self
                .current_state_identity()
                .is_ok_and(|value| value == plan.expected_identity)
            || !self
                .external_effect_generation()
                .is_ok_and(|value| value == plan.expected_generation)
            || !self.state.as_ref().is_some_and(|state| {
                state.engines.external_pki_mount_current(
                    &plan.namespace,
                    &plan.mount,
                    plan.mount_incarnation,
                )
            })
            || !self
                .outbound
                .same_https_enrollment(&plan.outbound, &plan.sign_url)
            || !self
                .outbound
                .same_https_enrollment(&plan.outbound, &plan.metadata_url)
        {
            return Response::error(
                503,
                "external PKI result withheld after authority/state changed; remote outcome unknown; no blind retry",
            );
        }
        let Some(mut candidate) = self.state.clone() else {
            return unknown();
        };
        let mut response = match candidate.engines.publish_external_pki(
            &plan.namespace,
            &plan.mount,
            plan.mount_incarnation,
            observation.material,
            &observation.signature,
        ) {
            Ok(value) => value,
            Err(cause) => return Response::error(cause.status, &cause.message),
        };
        candidate.schema = CURRENT_STATE_SCHEMA;
        if let Err(cause) = candidate.validate_format() {
            return cause;
        }
        let record_plan = match self.prepare_record_plan(&candidate) {
            Ok(value) => value,
            Err(cause) => return cause,
        };
        if let Err(cause) = self.commit_record_plan(&candidate, record_plan) {
            return cause;
        }
        self.state = Some(candidate);
        Response::ok(json!({"data":std::mem::take(&mut response.body)["data"].take()}))
    }
}
