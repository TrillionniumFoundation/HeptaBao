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
    genuine: Option<external_kms::Admitted>,
    genuine_jws: bool,
    metadata: Option<MetadataTarget>,
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
    // The original HA owner and role cannot be replaced by a new frontier.
    ha_admission: Option<ExternalTransitHaAdmission>,
    deadline: Option<std::time::Instant>,
    wrapping_ttl: Option<u64>,
    creation_path: String,
    publication_clock: super::external_pki::PublicationClock,
    // This checkpoint is created only after our own completed publication.
    // The original provider admission identity/generation above never change.
    delivery_checkpoint: Option<(
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    )>,
    wrapped_token: Option<Zeroizing<String>>,
}

pub(super) struct ExternalTransitHaAdmission {
    process: Arc<Mutex<HaProcess>>,
    role: (u64, u64),
}
impl ExternalTransitHaAdmission {
    pub(super) fn capture(
        ha: &Option<Arc<Mutex<HaProcess>>>,
        identity: crate::state_record_root::StateIdentity,
    ) -> Result<Option<Self>, Response> {
        let Some(ha) = ha else { return Ok(None) };
        let process = ha
            .lock_for_request()
            .map_err(|_| Response::error(503, "genuine KMS original HA owner unavailable"))?;
        process
            .ensure_application_identity(identity)
            .map_err(|_| Response::error(503, "genuine KMS original HA root unavailable"))?;
        let role = process
            .leader_status()
            .map_err(|_| Response::error(503, "genuine KMS original HA role unavailable"))?;
        if !role.local_is_leader || role.leader != Some(role.local_id) {
            return Err(Response::error(
                503,
                "genuine KMS original HA owner is not leader",
            ));
        }
        Ok(Some(Self {
            process: Arc::clone(ha),
            role: (role.local_id, role.term),
        }))
    }
    pub(super) fn current(&self, ha: &Option<Arc<Mutex<HaProcess>>>) -> bool {
        ha.as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.process))
    }
    pub(super) fn original_role(&self) -> (u64, u64) {
        self.role
    }

    pub(super) fn check_role(&self, process: &HaProcess) -> Result<(), Response> {
        let role = process
            .leader_status()
            .map_err(|_| Response::error(503, "external Transit original HA role unavailable"))?;
        if !role.local_is_leader
            || role.leader != Some(role.local_id)
            || (role.local_id, role.term) != self.role
        {
            return Err(Response::error(
                503,
                "external Transit original HA role changed; no blind retry",
            ));
        }
        Ok(())
    }

    pub(super) fn lock_original(
        &self,
        identity: crate::state_record_root::StateIdentity,
    ) -> Result<std::sync::MutexGuard<'_, HaProcess>, Response> {
        let process = self.process.lock_for_request().map_err(|_| {
            Response::error(503, "external Transit original HA role lock unavailable")
        })?;
        self.check_role(&process)?;
        process.ensure_application_identity(identity).map_err(|_| {
            Response::error(
                503,
                "external Transit original HA root changed; no blind retry",
            )
        })?;
        // ReadIndex itself can observe an election. Retain the same role afterward.
        self.check_role(&process)?;
        Ok(process)
    }
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
    fn original_ha_binding_current(&self, current: &Option<Arc<Mutex<HaProcess>>>) -> bool {
        match (&self.ha_admission, current) {
            (None, None) => true,
            (Some(admission), Some(current)) => Arc::ptr_eq(&admission.process, current),
            _ => false,
        }
    }

    fn lock_original_ha(
        &self,
        identity: crate::state_record_root::StateIdentity,
    ) -> Result<Option<std::sync::MutexGuard<'_, HaProcess>>, Response> {
        self.ha_admission
            .as_ref()
            .map(|admission| admission.lock_original(identity))
            .transpose()
    }

    pub(super) fn execute(&self) -> Result<Observation, Response> {
        let _deadline_scope = self
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        // Only the original leader may enter the unlocked external RPC.
        drop(self.lock_original_ha(self.expected_identity)?);
        if self.authority.deadline_expired() {
            return Err(Response::error(
                503,
                "external Transit rejected before entry: deadline",
            ));
        }
        if self.genuine.is_some() {
            return self.execute_genuine();
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

struct MetadataTarget {
    plugin_id: String,
    config: bool,
    values: SecretValue,
}
impl ExternalTransitPlan {
    fn owner_current(&self, state: &State) -> bool {
        if let Some(target) = &self.metadata {
            state
                .engines
                .external_parameter_read(&self.namespace, "GET", &self.creation_path)
                .is_ok_and(|read| {
                    read.is_some_and(|read| {
                        read.plugin_id == target.plugin_id
                            && read.config == target.config
                            && read.values.expose() == target.values.expose()
                    })
                })
        } else {
            state.engines.external_transit_mount_current(
                &self.namespace,
                &self.mount,
                self.mount_incarnation,
            )
        }
    }
    fn enrollment_current(&self, outbound: &crate::outbound::Outbound) -> bool {
        self.genuine.is_some() || outbound.same_https_enrollment(&self.outbound, &self.url)
    }
    fn retained_provider(&self) -> Option<SharedKmsPlugin> {
        self.genuine
            .as_ref()
            .map(external_kms::Admitted::host)
            .or_else(|| {
                self.provider_binding
                    .as_ref()
                    .map(|(host, _, _)| Arc::clone(host))
            })
    }
    fn provider_current_locked(
        &self,
        service: &Service,
        guard: Option<
            &heptabao_plugin_host::PluginHost<heptabao_plugin_host::CommandSandboxRunner>,
        >,
    ) -> bool {
        if let Some(genuine) = &self.genuine {
            genuine.current(&service.external_kms_plugins)
                && guard.is_some_and(|guard| genuine.host_current(guard))
        } else {
            !service.external_kms_plugins.contains_key("transit")
                && match (
                    &self.provider_binding,
                    service.kms_plugins.get("transit"),
                    service.kms_keys.get("transit"),
                    guard,
                ) {
                    (None, None, None, None) => true,
                    (
                        Some((host, binding, generation)),
                        Some(current_host),
                        Some(current_binding),
                        Some(guard),
                    ) => {
                        Arc::ptr_eq(host, current_host)
                            && provider_binding_matches(binding, current_binding)
                            && guard.state() == PluginHostState::Active
                            && guard.manifest().descriptor().generation() == *generation
                    }
                    _ => false,
                }
        }
    }
    fn provider_current(&self, service: &Service) -> bool {
        let retained = self.retained_provider();
        let guard = match retained.as_ref() {
            Some(host) => match host.try_lock() {
                Ok(guard) => Some(guard),
                Err(_) => return false,
            },
            None => None,
        };
        self.provider_current_locked(service, guard.as_deref())
    }
    fn execute_genuine(&self) -> Result<Observation, Response> {
        use heptabao_plugin_host::kms_bridge::{Operation, ProviderResult};
        let genuine = self
            .genuine
            .as_ref()
            .ok_or_else(|| Response::error(503, "genuine KMS plan owner unavailable"))?;
        let result = genuine.execute()?;
        let data = match result {
            ProviderResult::Metadata(metadata) => {
                let target = self.metadata.as_ref().ok_or_else(|| {
                    Response::error(503, "genuine KMS metadata target unavailable")
                })?;
                let mut values = SensitiveJson(
                    crate::auth::parse_strict_json(target.values.expose()).map_err(|_| {
                        Response::error(503, "genuine KMS metadata parameters unavailable")
                    })?,
                );
                metadata
                    .redact(&mut values.0, target.config)
                    .map_err(plugin::failure)?;
                if target.config {
                    values
                        .0
                        .as_object_mut()
                        .ok_or_else(|| {
                            Response::error(503, "genuine KMS metadata parameters unavailable")
                        })?
                        .insert("plugin".into(), json!(target.plugin_id));
                }
                std::mem::take(&mut values.0)
            }
            ProviderResult::Bytes { operation, encoded } => {
                let expected = match self.operation {
                    "encrypt" => Operation::Encrypt,
                    "decrypt" => Operation::Decrypt,
                    "sign" => Operation::Sign,
                    _ => {
                        return Err(Response::error(
                            503,
                            "genuine KMS cryptographic result kind mismatch",
                        ));
                    }
                };
                if operation != expected {
                    return Err(Response::error(
                        503,
                        "genuine KMS cryptographic result kind mismatch",
                    ));
                }
                let payload = std::str::from_utf8(encoded.expose()).map_err(|_| {
                    Response::error(503, "genuine KMS cryptographic encoding invalid")
                })?;
                let bytes = Zeroizing::new(BASE64.decode(payload).map_err(|_| {
                    Response::error(503, "genuine KMS cryptographic encoding invalid")
                })?);
                match operation {
                    Operation::Encrypt if !bytes.is_empty() && bytes.len() <= 64 * 1024 + 64 => {
                        json!({"ciphertext":format!("vault:v{}:{}",self.local_version,payload),"key_version":self.local_version})
                    }
                    Operation::Decrypt if bytes.len() <= 64 * 1024 => json!({"plaintext":payload}),
                    Operation::Sign if !bytes.is_empty() && bytes.len() <= 16 * 1024 => {
                        let value = if self.genuine_jws {
                            BASE64_URL.encode(&*bytes)
                        } else {
                            payload.to_owned()
                        };
                        json!({"signature":format!("vault:v{}:{}",self.local_version,value),"key_version":self.local_version})
                    }
                    _ => {
                        return Err(Response::error(
                            503,
                            "genuine KMS cryptographic result exceeds bound",
                        ));
                    }
                }
            }
            ProviderResult::Verified(valid) if self.operation == "verify" => json!({"valid":valid}),
            ProviderResult::Rejected => {
                return Ok(Observation {
                    data: Value::Null,
                    rejected: true,
                });
            }
            ProviderResult::NotImplemented => {
                return Err(Response::error(
                    501,
                    "genuine KMS provider operation is not implemented",
                ));
            }
            _ => {
                return Err(Response::error(
                    503,
                    "genuine KMS cryptographic result kind mismatch",
                ));
            }
        };
        Ok(Observation {
            data,
            rejected: false,
        })
    }
}

impl Service {
    pub(super) fn stage_genuine_kms_metadata(
        &mut self,
        state: &State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
        target: crate::engines::ExternalParameterRead,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "missing client token");
        };
        let Some(capability) =
            state
                .engines
                .required_capability(request.namespace, request.method, request.path)
        else {
            return Response::error(404, "external key route not found");
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
        if !request.body.as_object().is_some_and(|m| m.is_empty()) {
            return Response::error(400, "external key read contains unsupported fields");
        }
        if self.pending_external_transit.is_some() {
            return Response::error(503, "another external KMS operation is pending");
        }
        let input = match SecretValue::new(b"{}".to_vec()) {
            Ok(v) => v,
            Err(_) => return Response::error(503, "genuine KMS private input unavailable"),
        };
        let genuine = match external_kms::prepare(
            &self.external_kms_plugins,
            &target.plugin_id,
            heptabao_plugin_host::kms_bridge::Operation::Metadata,
            &input,
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return Response::error(503, "genuine KMS owner vanished before entry"),
            Err(e) => return e,
        };
        let expected_identity = match self.current_state_identity() {
            Ok(v) => v,
            Err(e) => return e,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ha_admission = match &self.ha {
            None => None,
            Some(ha) => {
                let process = match ha.lock_for_request() {
                    Ok(p) => p,
                    Err(_) => {
                        return Response::error(503, "genuine KMS original HA role unavailable");
                    }
                };
                if process
                    .ensure_application_identity(expected_identity)
                    .is_err()
                {
                    return Response::error(503, "genuine KMS original HA root unavailable");
                }
                let role = match process.leader_status() {
                    Ok(r) if r.local_is_leader && r.leader == Some(r.local_id) => r,
                    _ => {
                        return Response::error(
                            503,
                            "genuine KMS original HA admission is not leader",
                        );
                    }
                };
                Some(ExternalTransitHaAdmission {
                    process: Arc::clone(ha),
                    role: (role.local_id, role.term),
                })
            }
        };
        self.pending_external_transit = Some(ExternalTransitPlan {
            request: input,
            genuine: Some(genuine),
            genuine_jws: false,
            metadata: Some(MetadataTarget {
                plugin_id: target.plugin_id,
                config: target.config,
                values: target.values,
            }),
            operation: "metadata",
            local_version: 0,
            mount: String::new(),
            mount_incarnation: 0,
            namespace: request.namespace.into(),
            url: String::new(),
            outbound: self.outbound.clone(),
            provider_binding: None,
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
            ha_admission,
            deadline: crate::request_deadline::current(),
            wrapping_ttl: request.wrap_ttl_seconds.filter(|ttl| *ttl > 0),
            creation_path: request.path.into(),
            publication_clock: super::external_pki::PublicationClock::capture(),
            delivery_checkpoint: None,
            wrapped_token: None,
        });
        Response::error(500, "genuine KMS metadata was not dispatched")
    }
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
        if self.pending_external_transit.is_some() {
            return Response::error(503, "another external Transit operation is pending");
        }
        let admitted = self.external_kms_plugins.keys().cloned().collect();
        let plan = match state.engines.prepare_external_transit_with_providers(
            request.namespace,
            request.method,
            request.path,
            request.body,
            &admitted,
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) => return Response::error(404, "external Transit route not found"),
            Err(error) => return Response::error(error.status, &error.message),
        };
        let envelope = match crate::auth::parse_strict_json(plan.request.expose()) {
            Ok(value) => SensitiveJson(value),
            Err(_) => return Response::error(503, "invalid external Transit plan"),
        };
        let operation = match plan.operation {
            "encrypt" => heptabao_plugin_host::kms_bridge::Operation::Encrypt,
            "decrypt" => heptabao_plugin_host::kms_bridge::Operation::Decrypt,
            "sign" => heptabao_plugin_host::kms_bridge::Operation::Sign,
            "verify" => heptabao_plugin_host::kms_bridge::Operation::Verify,
            _ => return Response::error(503, "invalid genuine KMS operation"),
        };
        let genuine = match plan.genuine_provider.as_deref() {
            Some(id) => match external_kms::prepare(
                &self.external_kms_plugins,
                id,
                operation,
                &plan.request,
            ) {
                Ok(Some(value)) => Some(value),
                Ok(None) => return Response::error(503, "genuine KMS owner vanished before entry"),
                Err(error) => return error,
            },
            None => None,
        };
        let genuine_jws = genuine.is_some() && envelope.0["marshaling"].as_str() == Some("jws");
        let url = if genuine.is_some() {
            ""
        } else {
            match envelope.0["url"].as_str() {
                Some(url) => url,
                None => return Response::error(503, "invalid external Transit route"),
            }
        };
        if genuine.is_none() && self.outbound.endpoint(url, "https").is_err() {
            return Response::error(
                503,
                "external Transit rejected before entry: HTTPS route is not deployment-enrolled",
            );
        }
        if genuine.is_none()
            && let Err(message) = self.outbound.validate_external_transit_tls(
                url,
                envelope.0["tls_server_name"].as_str().unwrap_or(""),
                envelope.0["tls_ca_cert_bytes"].as_str().unwrap_or(""),
            )
        {
            return Response::error(503, message);
        }
        // Built-in Transit uses verified native egress. If a deployment also
        // enrolled a KMS host under this identifier, its disable/capability
        // binding remains an additional authority fence; it is never an ack.
        let provider_binding = if genuine.is_some() {
            None
        } else {
            match (
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
                _ => {
                    return Response::error(503, "external Transit provider binding is incomplete");
                }
            }
        };
        let expected_identity = match self.current_state_identity() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let ha_admission = match &self.ha {
            None => None,
            Some(ha) => {
                let process = match ha.lock_for_request() {
                    Ok(process) => process,
                    Err(_) => {
                        return Response::error(
                            503,
                            "external Transit HA admission lock unavailable",
                        );
                    }
                };
                if process
                    .ensure_application_identity(expected_identity)
                    .is_err()
                {
                    return Response::error(503, "external Transit HA admission root unavailable");
                }
                let role = match process.leader_status() {
                    Ok(role) if role.local_is_leader && role.leader == Some(role.local_id) => role,
                    _ => {
                        return Response::error(503, "external Transit HA admission is not leader");
                    }
                };
                Some(ExternalTransitHaAdmission {
                    process: Arc::clone(ha),
                    role: (role.local_id, role.term),
                })
            }
        };
        self.pending_external_transit = Some(ExternalTransitPlan {
            genuine,
            genuine_jws,
            metadata: None,
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
            ha_admission,
            deadline: crate::request_deadline::current(),
            wrapping_ttl: request.wrap_ttl_seconds.filter(|ttl| *ttl > 0),
            creation_path: request.path.into(),
            publication_clock: super::external_pki::PublicationClock::capture(),
            delivery_checkpoint: None,
            wrapped_token: None,
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
        plan: &mut ExternalTransitPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let mut observation = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        if let Err(error) = self.validate_plugin_response(&mut plan.authority) {
            return error;
        }
        if !plan.original_ha_binding_current(&self.ha) {
            return Response::error(
                503,
                "external Transit original HA owner changed; no blind retry",
            );
        }
        if let Err(cause) = plan.lock_original_ha(plan.expected_identity) {
            return cause;
        }
        let provider_current = plan.provider_current(self);
        let state_current = self
            .current_state_identity()
            .is_ok_and(|identity| identity == plan.expected_identity);
        let generation_current = self
            .external_effect_generation()
            .is_ok_and(|generation| generation == plan.expected_generation);
        let mount_current = self
            .state
            .as_ref()
            .is_some_and(|state| plan.owner_current(state));
        if !plan.original_ha_binding_current(&self.ha)
            || !provider_current
            || !state_current
            || !generation_current
            || !mount_current
            || !plan.enrollment_current(&self.outbound)
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
            let mut response = Response::ok(json!({"data":std::mem::take(&mut observation.data)}));
            if let Err(cause) = self.publish_external_transit_wrapping(plan, &mut response) {
                erase_json(&mut response.body);
                return cause;
            }
            plan.delivery_checkpoint = match (
                self.current_state_identity(),
                self.external_effect_generation(),
            ) {
                (Ok(identity), Ok(generation)) => Some((identity, generation)),
                _ => {
                    erase_json(&mut response.body);
                    return Response::error(
                        503,
                        "external Transit delivery checkpoint unavailable; no blind retry",
                    );
                }
            };
            response
        }
    }

    fn publish_external_transit_wrapping(
        &mut self,
        plan: &mut ExternalTransitPlan,
        response: &mut Response,
    ) -> Result<(), Response> {
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let Some(ttl) = plan.wrapping_ttl else {
            return Ok(());
        };
        let mut candidate = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "external Transit wrapping owner unavailable"))?
            .clone();
        let time = plan.authority.observe_candidate_time(&mut candidate)?;
        let _origin_scope = plan.publication_clock.enter_scope();
        let mut wrapped = candidate
            .auth
            .wrap_logical_response(
                &plan.namespace,
                &plan.creation_path,
                ttl,
                &response.body,
                time.seconds(),
            )
            .map_err(|cause| Response::error(cause.status, &cause.message))?;
        let mut wrapped_body = SensitiveJson(std::mem::take(&mut wrapped.body));
        plan.wrapped_token = Some(Zeroizing::new(
            wrapped_body.0["wrap_info"]["token"]
                .as_str()
                .ok_or_else(|| {
                    Response::error(503, "external Transit private wrapper unavailable")
                })?
                .to_owned(),
        ));
        erase_json(&mut response.body);
        response.status = wrapped.status;
        response.body = std::mem::take(&mut wrapped_body.0);
        candidate.schema = candidate.writer_schema();
        candidate.validate_format()?;
        let record_plan = self.prepare_record_plan(&mut candidate)?;
        self.validate_plugin_response(&mut plan.authority)?;
        if !plan.original_ha_binding_current(&self.ha)
            || !self
                .current_state_identity()
                .is_ok_and(|identity| identity == plan.expected_identity)
            || !self
                .external_effect_generation()
                .is_ok_and(|generation| generation == plan.expected_generation)
            || !self
                .state
                .as_ref()
                .is_some_and(|state| plan.owner_current(state))
            || !plan.enrollment_current(&self.outbound)
        {
            return Err(Response::error(
                503,
                "external Transit wrapping withheld after owner changed; remote outcome unknown; no blind retry",
            ));
        }
        // Retain the optional host lock through the authenticated writer commit.
        // The native result remains the real HTTPS provider's cryptographic result.
        let retained_host = plan.retained_provider();
        let host_guard = match retained_host.as_ref() {
            Some(host) => Some(host.try_lock().map_err(|_| {
                Response::error(
                    503,
                    "external Transit provider host busy before wrapping publication",
                )
            })?),
            None => None,
        };
        let provider_current = plan.provider_current_locked(self, host_guard.as_deref());
        if !provider_current {
            return Err(Response::error(
                503,
                "external Transit provider changed before wrapping publication; no blind retry",
            ));
        }
        plan.authority.validate_live_auth(&candidate.auth)?;
        drop(plan.lock_original_ha(plan.expected_identity)?);
        self.commit_record_plan_with_native_role(
            &candidate,
            record_plan,
            plan.ha_admission.as_ref().map(|admission| admission.role),
            |auth| plan.authority.validate_live_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        )?;
        self.state = Some(candidate);
        Ok(())
    }

    pub(super) fn audit_external_transit_response(
        &mut self,
        plan: &mut ExternalTransitPlan,
        fingerprint: &str,
        request_clock: (u64, Option<RequestClock>),
        response: Response,
    ) -> Response {
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        let (response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint,
            request_clock,
            response,
            || {},
            true,
        );
        if (200..300).contains(&response.status)
            && let Some(receipt) = receipt
        {
            receipt.advance(&mut plan.delivery_checkpoint);
        }
        response
    }

    pub(super) fn complete_external_transit_delivery(
        &mut self,
        plan: &mut ExternalTransitPlan,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        let planned_success = (200..300).contains(&response.status);
        let mut response = self.external_transit_delivery_gate(plan, response);
        if planned_success
            && !(200..300).contains(&response.status)
            && self
                .audit_event(
                    "external-transit-delivery-veto",
                    fingerprint,
                    plan.authority.now(),
                    Some(response.status),
                )
                .is_err()
        {
            erase_json(&mut response.body);
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Response::error(
                503,
                "external Transit delivery veto audit failed; authoritative recovery required; no blind retry",
            );
        }
        response
    }

    fn external_transit_delivery_gate(
        &mut self,
        plan: &mut ExternalTransitPlan,
        mut response: Response,
    ) -> Response {
        let _deadline_scope = plan
            .deadline
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        if !(200..300).contains(&response.status) {
            return response;
        }
        if let Err(cause) = self.validate_plugin_response(&mut plan.authority) {
            erase_json(&mut response.body);
            return cause;
        }
        if !plan.original_ha_binding_current(&self.ha) {
            erase_json(&mut response.body);
            return Response::error(
                503,
                "external Transit original HA owner changed; no blind retry",
            );
        }
        let Some((identity, _)) = plan.delivery_checkpoint.as_ref() else {
            erase_json(&mut response.body);
            return Response::error(503, "external Transit delivery root unavailable");
        };
        if let Err(cause) = plan.lock_original_ha(*identity) {
            erase_json(&mut response.body);
            return cause;
        }
        let retained_host = plan.retained_provider();
        let host_guard = match retained_host.as_ref() {
            Some(host) => match host.try_lock() {
                Ok(guard) => Some(guard),
                Err(_) => {
                    erase_json(&mut response.body);
                    return Response::error(
                        503,
                        "external Transit provider host busy before delivery",
                    );
                }
            },
            None => None,
        };
        let provider_current = plan.provider_current_locked(self, host_guard.as_deref());
        let checkpoint_current =
            plan.delivery_checkpoint
                .as_ref()
                .is_some_and(|(identity, generation)| {
                    self.current_state_identity()
                        .is_ok_and(|current| current == *identity)
                        && self
                            .external_effect_generation()
                            .is_ok_and(|current| current == *generation)
                });
        if !plan.original_ha_binding_current(&self.ha)
            || !provider_current
            || !checkpoint_current
            || !self
                .state
                .as_ref()
                .is_some_and(|state| plan.owner_current(state))
            || !plan.enrollment_current(&self.outbound)
            || plan.authority.deadline_expired()
        {
            erase_json(&mut response.body);
            return Response::error(
                503,
                "external Transit committed response withheld by delivery fence; public readback required; no blind retry",
            );
        }
        if let Some(token) = plan.wrapped_token.as_ref() {
            let time = match plan.authority.token_time() {
                Ok(time) => time,
                Err(cause) => {
                    erase_json(&mut response.body);
                    return cause;
                }
            };
            let lookup = SensitiveJson(json!({"token":token.as_str()}));
            let live_wrapper = self.state.as_ref().is_some_and(|state| {
                state
                    .auth
                    .lookup_wrapping_request("", &plan.namespace, "POST", &lookup.0, time.seconds())
                    .is_ok_and(|metadata| {
                        metadata.body["data"]["creation_path"] == plan.creation_path
                            && metadata.body["data"]["creation_ttl"].as_u64() == plan.wrapping_ttl
                    })
            });
            if !live_wrapper {
                erase_json(&mut response.body);
                return Response::error(
                    503,
                    "external Transit committed wrapper no longer live before delivery; no blind retry",
                );
            }
        }
        let Some((identity, expected_generation)) = plan.delivery_checkpoint.as_ref() else {
            erase_json(&mut response.body);
            return Response::error(503, "external Transit delivery root unavailable");
        };
        // Acquire only after the ordinary identity/frontier reads; retaining this
        // lock through return fences the same original term at actual delivery.
        let _original_ha_guard = match plan.lock_original_ha(*identity) {
            Ok(guard) => guard,
            Err(cause) => {
                erase_json(&mut response.body);
                return cause;
            }
        };
        let final_generation = match _original_ha_guard.as_ref() {
            Some(process) => self.external_effect_generation_with_retained_ha(process),
            None => self.external_effect_generation(),
        };
        if !final_generation.is_ok_and(|current| current == *expected_generation) {
            erase_json(&mut response.body);
            return Response::error(
                503,
                "external Transit final HA frontier changed; no blind retry",
            );
        }
        // Lock/ReadIndex waits spend the original clock and deadline.
        if let Err(cause) = self
            .state
            .as_ref()
            .ok_or_else(|| Response::error(503, "external Transit delivery owner unavailable"))
            .and_then(|state| plan.authority.validate_live_auth(&state.auth))
        {
            erase_json(&mut response.body);
            return cause;
        }
        if let (Some(admission), Some(process)) =
            (plan.ha_admission.as_ref(), _original_ha_guard.as_ref())
            && let Err(cause) = admission.check_role(process)
        {
            erase_json(&mut response.body);
            return cause;
        }
        response
    }
}
