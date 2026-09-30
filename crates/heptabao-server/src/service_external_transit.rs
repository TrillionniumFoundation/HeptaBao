//! Native remote Transit consumer on the existing audited external-effect owner.
//! Only a deployment-enrolled HTTPS route can be entered. Whole durable-state
//! fencing is conservative: even unrelated writes withhold a delayed result.
use super::plugin::{KmsKeyBinding, PluginResponseAuthority, SharedKmsPlugin};
use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use heptabao_domain::SecretValue;
use heptabao_kms_contracts::KmsCapability;
use heptabao_plugin_host::PluginHostState;
use std::sync::Arc;
use zeroize::Zeroizing;

pub(super) struct ExternalTransitPlan {
    request: SecretValue,
    operation: &'static str,
    local_version: u64,
    mount: String,
    mount_incarnation: u64,
    namespace: String,
    url: String,
    outbound: crate::outbound::Outbound,
    provider_binding: Option<(SharedKmsPlugin, KmsKeyBinding, u64)>,
    expected_identity: crate::state_record_root::StateIdentity,
    expected_generation: plugin::PublicationGeneration,
    authority: PluginResponseAuthority,
}

struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}

pub(crate) struct Observation {
    data: Value,
    rejected: bool,
}
impl Drop for Observation {
    fn drop(&mut self) {
        erase_json(&mut self.data);
    }
}

fn provider_host_generation(host: &SharedKmsPlugin) -> Option<u64> {
    let host = host.try_lock().ok()?;
    (host.state() == PluginHostState::Active).then(|| host.manifest().descriptor().generation())
}

fn provider_binding_matches(left: &KmsKeyBinding, right: &KmsKeyBinding) -> bool {
    left.enabled
        && right.enabled
        && left.key_id == right.key_id
        && left.key_version == right.key_version
        && left.capabilities == right.capabilities
}

impl ExternalTransitPlan {
    pub(super) fn execute(&self) -> Result<Observation, Response> {
        if self.authority.deadline_expired() {
            return Err(Response::error(
                503,
                "external Transit rejected before entry: deadline",
            ));
        }
        let envelope = SensitiveJson(
            crate::auth::parse_strict_json(self.request.expose())
                .map_err(|_| Response::error(503, "invalid external Transit plan"))?,
        );
        let token = envelope.0["token"]
            .as_str()
            .ok_or_else(|| Response::error(503, "invalid external Transit credential"))?;
        let namespace = envelope.0["namespace"]
            .as_str()
            .ok_or_else(|| Response::error(503, "invalid external Transit namespace"))?;
        let remote_version = envelope.0["remote_version"]
            .as_u64()
            .ok_or_else(|| Response::error(503, "invalid external Transit version"))?;
        let response = self
            .outbound
            .post_external_transit(&self.url, token, namespace, &envelope.0["body"])
            .map_err(|message| Response::error(503, message))?;
        let response = match response {
            crate::outbound::ExternalTransitResponse::Crypto(value) => SensitiveJson(value),
            crate::outbound::ExternalTransitResponse::Rejected => {
                return Ok(Observation {
                    data: Value::Null,
                    rejected: true,
                });
            }
        };
        let data = response.0.get("data").and_then(Value::as_object)
            .ok_or_else(|| Response::error(503,"external Transit unknown after entry: missing cryptographic result; no blind retry"))?;
        let result = match self.operation {
            "encrypt" => {
                if data
                    .keys()
                    .any(|key| !matches!(key.as_str(), "ciphertext" | "key_version"))
                    || data
                        .get("key_version")
                        .is_some_and(|value| value.as_u64() != Some(remote_version))
                {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: result binding mismatch; no blind retry",
                    ));
                }
                let ciphertext = data.get("ciphertext").and_then(Value::as_str)
                    .ok_or_else(|| Response::error(503,"external Transit unknown after entry: ciphertext missing; no blind retry"))?;
                let prefix = format!("vault:v{remote_version}:");
                let payload = ciphertext.strip_prefix(&prefix).filter(|value| !value.is_empty())
                    .ok_or_else(|| Response::error(503,"external Transit unknown after entry: ciphertext version mismatch; no blind retry"))?;
                let bytes = Zeroizing::new(BASE64.decode(payload).map_err(|_| {
                    Response::error(
                        503,
                        "external Transit unknown after entry: invalid ciphertext; no blind retry",
                    )
                })?);
                if bytes.len() < 28 || bytes.len() > 64 * 1024 + 64 {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: ciphertext bound; no blind retry",
                    ));
                }
                json!({"ciphertext":format!("vault:v{}:{}",self.local_version,payload),
                    "key_version":self.local_version})
            }
            "decrypt" => {
                if data.len() != 1 {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: plaintext fields mismatch; no blind retry",
                    ));
                }
                let plaintext = data.get("plaintext").and_then(Value::as_str)
                    .ok_or_else(|| Response::error(503,"external Transit unknown after entry: plaintext missing; no blind retry"))?;
                let bytes = Zeroizing::new(BASE64.decode(plaintext).map_err(|_| {
                    Response::error(
                        503,
                        "external Transit unknown after entry: invalid plaintext; no blind retry",
                    )
                })?);
                if bytes.len() > 64 * 1024 {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: plaintext bound; no blind retry",
                    ));
                }
                json!({"plaintext":plaintext})
            }
            "sign" => {
                if data
                    .keys()
                    .any(|key| !matches!(key.as_str(), "signature" | "key_version"))
                    || data
                        .get("key_version")
                        .is_some_and(|value| value.as_u64() != Some(remote_version))
                {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: signature binding mismatch; no blind retry",
                    ));
                }
                let signature = data.get("signature").and_then(Value::as_str)
                    .ok_or_else(|| Response::error(503, "external Transit unknown after entry: signature missing; no blind retry"))?;
                let prefix = format!("vault:v{remote_version}:");
                let payload = signature.strip_prefix(&prefix).filter(|value| !value.is_empty())
                    .ok_or_else(|| Response::error(503, "external Transit unknown after entry: signature version mismatch; no blind retry"))?;
                let encoding = if envelope.0["body"]["marshaling_algorithm"] == "jws" {
                    &BASE64_URL
                } else {
                    &BASE64
                };
                let bytes = Zeroizing::new(encoding.decode(payload).map_err(|_| {
                    Response::error(
                        503,
                        "external Transit unknown after entry: invalid signature; no blind retry",
                    )
                })?);
                if bytes.is_empty() || bytes.len() > 16 * 1024 {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: signature bound; no blind retry",
                    ));
                }
                json!({"signature":format!("vault:v{}:{}", self.local_version, payload), "key_version":self.local_version})
            }
            "verify" => {
                if data.len() != 1 || data.get("valid").and_then(Value::as_bool).is_none() {
                    return Err(Response::error(
                        503,
                        "external Transit unknown after entry: verification result mismatch; no blind retry",
                    ));
                }
                json!({"valid":data["valid"]})
            }
            _ => {
                return Err(Response::error(
                    503,
                    "external Transit plan operation mismatch",
                ));
            }
        };
        Ok(Observation {
            data: result,
            rejected: false,
        })
    }
}

impl Service {
    pub(super) fn stage_external_transit(
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
            return Response::error(404, "Transit route not found");
        };
        if let Err(error) = state.auth.authorize_request(
            &principal,
            request.namespace,
            request.path,
            capability,
            request.now,
        ) {
            return Response::error(error.status, &error.message);
        }
        if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) {
            return Response::error(501, "external Transit response wrapping is not implemented");
        }
        if self.pending_external_transit.is_some() {
            return Response::error(503, "another external Transit operation is pending");
        }
        let plan = match state.engines.prepare_external_transit(
            request.namespace,
            request.method,
            request.path,
            request.body,
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) => return Response::error(404, "external Transit route not found"),
            Err(error) => return Response::error(error.status, &error.message),
        };
        let envelope = match crate::auth::parse_strict_json(plan.request.expose()) {
            Ok(value) => SensitiveJson(value),
            Err(_) => return Response::error(503, "invalid external Transit plan"),
        };
        let Some(url) = envelope.0["url"].as_str() else {
            return Response::error(503, "invalid external Transit route");
        };
        if self.outbound.endpoint(url, "https").is_err() {
            return Response::error(
                503,
                "external Transit rejected before entry: HTTPS route is not deployment-enrolled",
            );
        }
        // Built-in Transit uses verified native egress. If a deployment also
        // enrolled a KMS host under this identifier, its disable/capability
        // binding remains an additional authority fence; it is never an ack.
        let provider_binding = match (
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
        ) {
            (Some(host), Some(binding)) => {
                let capability = match plan.operation {
                    "encrypt" => KmsCapability::Wrap,
                    "decrypt" => KmsCapability::Unwrap,
                    "sign" => KmsCapability::Sign,
                    "verify" => KmsCapability::Verify,
                    _ => return Response::error(503, "invalid external Transit operation"),
                };
                if !binding.enabled || !binding.capabilities.contains(&capability) {
                    return Response::error(
                        403,
                        "external Transit provider is disabled or lacks capability",
                    );
                }
                let Some(generation) = provider_host_generation(host) else {
                    return Response::error(
                        503,
                        "external Transit rejected before entry: KMS host is busy, revoked or requires reconciliation",
                    );
                };
                Some((Arc::clone(host), binding.clone(), generation))
            }
            (None, None) => None,
            _ => return Response::error(503, "external Transit provider binding is incomplete"),
        };
        let expected_identity = match self.current_state_identity() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_external_transit = Some(ExternalTransitPlan {
            request: plan.request,
            operation: plan.operation,
            local_version: plan.local_version,
            mount: plan.mount,
            mount_incarnation: plan.mount_incarnation,
            namespace: request.namespace.into(),
            url: url.into(),
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
        });
        Response::error(500, "external Transit was not dispatched")
    }

    pub(super) fn finalize_external_transit(
        &mut self,
        mut plan: ExternalTransitPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let mut observation = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            return error;
        }
        let provider_current = match (
            &plan.provider_binding,
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
        ) {
            (None, None, None) => true,
            (Some((host, binding, generation)), Some(current_host), Some(current_binding)) => {
                Arc::ptr_eq(host, current_host)
                    && provider_binding_matches(binding, current_binding)
                    && provider_host_generation(current_host) == Some(*generation)
            }
            _ => false,
        };
        let state_current = self
            .current_state_identity()
            .is_ok_and(|identity| identity == plan.expected_identity);
        let generation_current = self
            .external_effect_generation()
            .is_ok_and(|generation| generation == plan.expected_generation);
        let mount_current = self.state.as_ref().is_some_and(|state| {
            state.engines.external_transit_mount_current(
                &plan.namespace,
                &plan.mount,
                plan.mount_incarnation,
            )
        });
        if !provider_current
            || !state_current
            || !generation_current
            || !mount_current
            || !self
                .outbound
                .same_https_enrollment(&plan.outbound, &plan.url)
        {
            return Response::error(
                503,
                "external Transit result withheld after authority/state changed; remote outcome unknown; no blind retry",
            );
        }
        if observation.rejected {
            let status = if matches!(plan.operation, "sign" | "verify") {
                500
            } else {
                400
            };
            Response::error(status, "external Transit provider rejected request")
        } else {
            Response::ok(json!({"data":std::mem::take(&mut observation.data)}))
        }
    }
}
