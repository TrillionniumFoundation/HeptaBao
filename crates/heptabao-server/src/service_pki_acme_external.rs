//! Public ACME signing retains its original verified order and ingress capsule.
//! An account proof never becomes a Vault Principal or renews a request deadline.
use super::plugin::{KmsKeyBinding, SharedKmsPlugin};
use super::*;
use crate::engines::{AcmeExternalFinalize, AcmeView};
use base64::engine::general_purpose::STANDARD as BASE64;
use heptabao_kms_contracts::KmsCapability;
use heptabao_plugin_host::PluginHostState;
use std::sync::Arc;
use zeroize::Zeroizing;

struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}
fn unknown() -> Response {
    Response::error(503, "ACME external signer result unknown; no blind retry")
}
fn crypto_response(
    value: crate::outbound::ExternalTransitResponse,
) -> Result<SensitiveJson, Response> {
    match value {
        crate::outbound::ExternalTransitResponse::Crypto(value) => Ok(SensitiveJson(value)),
        crate::outbound::ExternalTransitResponse::Rejected => Err(Response::error(
            500,
            "ACME external signer rejected signing",
        )),
    }
}
// This process-local receipt remains in the original ACME response capsule
// after the signing Plan and its publication lock have been consumed.
pub(super) struct ProviderReceipt {
    sign_url: String,
    metadata_url: String,
    outbound: crate::outbound::Outbound,
    binding: Option<(SharedKmsPlugin, KmsKeyBinding, u64)>,
}
impl ProviderReceipt {
    pub(super) fn check(&self, service: &Service) -> Result<(), Response> {
        if ![&self.sign_url, &self.metadata_url]
            .iter()
            .all(|url| service.outbound.same_https_enrollment(&self.outbound, url))
        {
            return Err(Response::error(
                503,
                "ACME external signer enrollment changed before delivery",
            ));
        }
        let current = match (
            &self.binding,
            service.kms_plugins.get("transit"),
            service.kms_keys.get("transit"),
        ) {
            (None, None, None) => true,
            (Some((host, binding, generation)), Some(current), Some(current_binding)) => {
                Arc::ptr_eq(host, current)
                    && binding.enabled
                    && current_binding.enabled
                    && binding.key_id == current_binding.key_id
                    && binding.key_version == current_binding.key_version
                    && binding.capabilities == current_binding.capabilities
                    && binding.capabilities.contains(&KmsCapability::Sign)
                    && host.try_lock().is_ok_and(|guard| {
                        guard.state() == PluginHostState::Active
                            && guard.manifest().descriptor().generation() == *generation
                    })
            }
            _ => false,
        };
        if !current {
            return Err(Response::error(
                503,
                "ACME external signer host authority changed before delivery",
            ));
        }
        Ok(())
    }
}

pub(super) struct Plan {
    pub(super) authority: Option<super::pki_acme::Authority>,
    engine: Option<AcmeExternalFinalize>,
    view: AcmeView,
    // This immutable admission snapshot checks elapsed authorization lifetime
    // between provider calls. Only the final writer can check current live state.
    snapshot: State,
    sign_url: String,
    metadata_url: String,
    outbound: crate::outbound::Outbound,
    provider_binding: Option<(SharedKmsPlugin, KmsKeyBinding, u64)>,
    expected_identity: crate::state_record_root::StateIdentity,
    expected_generation: plugin::PublicationGeneration,
}
impl Plan {
    fn authority(&self) -> Result<&super::pki_acme::Authority, Response> {
        self.authority.as_ref().ok_or_else(unknown)
    }
    fn provider_host_current(&self) -> bool {
        self.provider_binding
            .as_ref()
            .is_none_or(|(host, binding, generation)| {
                host.try_lock().is_ok_and(|host| {
                    binding.enabled
                        && binding.capabilities.contains(&KmsCapability::Sign)
                        && host.state() == PluginHostState::Active
                        && host.manifest().descriptor().generation() == *generation
                })
            })
    }
    fn check_before_effect(&self) -> Result<(), Response> {
        let authority = self.authority()?;
        authority.check_state(&self.snapshot)?;
        if !self.provider_host_current() {
            return Err(Response::error(
                503,
                "ACME external signer host authority changed",
            ));
        }
        self.engine
            .as_ref()
            .ok_or_else(unknown)?
            .validate_before_effect(&self.snapshot.engines, authority.observed_at()?)
            .map_err(Response::from_engine_error)
    }
    fn enrollment_current(&self, outbound: &crate::outbound::Outbound) -> bool {
        [&self.sign_url, &self.metadata_url]
            .iter()
            .all(|url| outbound.same_https_enrollment(&self.outbound, url))
    }
    pub(super) fn execute(&self) -> Result<Zeroizing<Vec<u8>>, Response> {
        let _scope = self
            .authority()?
            .deadline()
            .map(crate::request_deadline::RequestDeadlineScope::enter);
        self.check_before_effect()?;
        let engine = self.engine.as_ref().ok_or_else(unknown)?;
        let envelope = SensitiveJson(
            crate::auth::parse_strict_json(engine.request.expose()).map_err(|_| unknown())?,
        );
        let token = envelope.0["token"].as_str().ok_or_else(unknown)?;
        let namespace = envelope.0["namespace"].as_str().ok_or_else(unknown)?;
        let version = envelope.0["remote_version"].as_u64().ok_or_else(unknown)?;
        let metadata = crypto_response(
            self.outbound
                .get_external_transit(&self.metadata_url, token, namespace)
                .map_err(|error| Response::error(503, error))?,
        )?;
        let data = metadata.0["data"].as_object().ok_or_else(unknown)?;
        if data.get("supports_signing").and_then(Value::as_bool) != Some(true)
            || data.get("latest_version").and_then(Value::as_u64) != Some(version)
        {
            return Err(Response::error(500, "ACME external signer version changed"));
        }
        let kind = data
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(unknown)?;
        let key = data
            .get("keys")
            .and_then(Value::as_object)
            .and_then(|keys| keys.get(&version.to_string()))
            .and_then(|key| key.get("public_key"))
            .and_then(Value::as_str)
            .ok_or_else(unknown)?;
        let public = crate::engines::ExternalPkiPublicKey::from_metadata(kind, key)
            .map_err(Response::from_engine_error)?;
        engine
            .template
            .validate_provider_public(&public)
            .map_err(Response::from_engine_error)?;
        self.check_before_effect()?;
        let input = engine
            .template
            .signing_input()
            .map_err(Response::from_engine_error)?;
        let mut body = SensitiveJson(
            json!({"input":BASE64.encode(input),"key_version":version.to_string(),"prehashed":engine.template.hash_algorithm().is_some(),"signature_algorithm":engine.template.signature_algorithm()}),
        );
        if let Some(hash) = engine.template.hash_algorithm() {
            body.0["hash_algorithm"] = json!(hash);
        }
        if engine.template.signature_algorithm() == "pss" {
            body.0["salt_length"] = json!("hash");
        }
        // No metadata read or TBS preparation can extend this original deadline.
        self.check_before_effect()?;
        let signed = crypto_response(
            self.outbound
                .put_external_transit(&self.sign_url, token, namespace, &body.0)
                .map_err(|error| Response::error(503, error))?,
        )?;
        let data = signed.0["data"].as_object().ok_or_else(unknown)?;
        if data
            .keys()
            .any(|key| !matches!(key.as_str(), "signature" | "key_version"))
            || data
                .get("key_version")
                .is_some_and(|key| key.as_u64() != Some(version))
        {
            return Err(unknown());
        }
        let prefix = format!("vault:v{version}:");
        let signature = data
            .get("signature")
            .and_then(Value::as_str)
            .and_then(|signature| signature.strip_prefix(&prefix))
            .ok_or_else(unknown)?;
        if signature.is_empty()
            || signature.len() > engine.template.signature_size_bound().div_ceil(3) * 4
        {
            return Err(unknown());
        }
        let signature = Zeroizing::new(BASE64.decode(signature).map_err(|_| unknown())?);
        if BASE64.encode(&*signature)
            != data["signature"]
                .as_str()
                .and_then(|signature| signature.strip_prefix(&prefix))
                .ok_or_else(unknown)?
        {
            return Err(unknown());
        }
        self.check_before_effect()?;
        Ok(signature)
    }
}
impl Service {
    pub(super) fn stage_acme_external(
        &mut self,
        state: &State,
        view: &AcmeView,
        authority: &mut Option<super::pki_acme::Authority>,
        engine: AcmeExternalFinalize,
    ) -> Response {
        if self.pending_acme_external.is_some() {
            return unknown();
        }
        let Some(original) = authority.as_ref() else {
            return unknown();
        };
        if let Err(error) = original.check(self) {
            return error;
        }
        if let Err(error) = engine.validate_before_effect(
            &state.engines,
            match original.observed_at() {
                Ok(at) => at,
                Err(error) => return error,
            },
        ) {
            return Response::from_engine_error(error);
        }
        let (sign_url, metadata_url) =
            match super::external_pki::enrolled_pki_routes(&self.outbound, &engine.request) {
                Ok(routes) => routes,
                Err(error) => return error,
            };
        let provider_binding = match (
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
        ) {
            (Some(host), Some(binding)) => {
                if !binding.enabled || !binding.capabilities.contains(&KmsCapability::Sign) {
                    return Response::error(
                        403,
                        "ACME external signer disabled or lacks signing capability",
                    );
                }
                let Ok(guard) = host.try_lock() else {
                    return Response::error(503, "ACME external signer host busy");
                };
                if guard.state() != PluginHostState::Active {
                    return Response::error(503, "ACME external signer host revoked");
                }
                Some((
                    Arc::clone(host),
                    binding.clone(),
                    guard.manifest().descriptor().generation(),
                ))
            }
            (None, None) => None,
            _ => return Response::error(503, "ACME external signer binding incomplete"),
        };
        let expected_identity = match self.current_state_identity() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let expected_generation = match self.external_effect_generation() {
            Ok(value) => value,
            Err(error) => return error,
        };
        let Some(original) = authority.as_mut() else {
            return unknown();
        };
        original.bind_external_provider(ProviderReceipt {
            sign_url: sign_url.clone(),
            metadata_url: metadata_url.clone(),
            outbound: self.outbound.clone(),
            binding: provider_binding.clone(),
        });
        self.pending_acme_external = Some(Plan {
            authority: authority.take(),
            engine: Some(engine),
            view: view.clone(),
            snapshot: state.clone(),
            sign_url,
            metadata_url,
            outbound: self.outbound.clone(),
            provider_binding,
            expected_identity,
            expected_generation,
        });
        Response::error(500, "ACME external signing was not dispatched")
    }
    pub(super) fn finalize_acme_external(
        &mut self,
        plan: &mut Plan,
        result: Result<Zeroizing<Vec<u8>>, Response>,
    ) -> Response {
        let signature = match result {
            Ok(value) => value,
            Err(error) => return error,
        };
        let _scope = match plan.authority() {
            Ok(authority) => authority.deadline(),
            Err(error) => return error,
        }
        .map(crate::request_deadline::RequestDeadlineScope::enter);
        match plan.authority() {
            Ok(authority) => {
                if let Err(error) = authority.check(self) {
                    return error;
                }
            }
            Err(error) => return error,
        }
        let retained = plan
            .provider_binding
            .as_ref()
            .map(|(host, _, _)| Arc::clone(host));
        let host_guard = if let Some(host) = retained.as_ref() {
            match host.try_lock() {
                Ok(host) => Some(host),
                Err(_) => {
                    return Response::error(503, "ACME external signer busy before publication");
                }
            }
        } else {
            None
        };
        let host_current = match (
            &plan.provider_binding,
            self.kms_plugins.get("transit"),
            self.kms_keys.get("transit"),
            host_guard.as_ref(),
        ) {
            (None, None, None, None) => true,
            (
                Some((host, binding, generation)),
                Some(current),
                Some(current_binding),
                Some(guard),
            ) => {
                Arc::ptr_eq(host, current)
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
        if !host_current
            || !self
                .current_state_identity()
                .is_ok_and(|identity| identity == plan.expected_identity)
            || !self
                .external_effect_generation()
                .is_ok_and(|generation| generation == plan.expected_generation)
            || !plan.enrollment_current(&self.outbound)
        {
            return Response::error(
                503,
                "ACME external result withheld after owner changed; remote outcome unknown; no blind retry",
            );
        }
        let Some(authority) = plan.authority.as_mut() else {
            return unknown();
        };
        let Some(mut candidate) = self.state.clone() else {
            return unknown();
        };
        let at = match authority.observed_at() {
            Ok(at) => candidate.engines.acme_observed_time(at),
            Err(error) => return error,
        };
        let Some(engine) = plan.engine.take() else {
            return unknown();
        };
        let (body, location, delivery) = match candidate
            .engines
            .publish_acme_external_finalize(engine, &signature, at)
        {
            Ok(value) => value,
            Err(error) => return Response::from_engine_error(error),
        };
        authority.bind_external_delivery(delivery);
        let headers = match ResponseHeaders::from_sdk(
            Some(&json!({"Location":[location]})),
            &plan.view.headers,
        ) {
            Ok(headers) => headers,
            Err(()) => return unknown(),
        };
        let mut response = super::pki_acme::wire(200, Some(body), false, headers);
        if let Err(error) = self.decorate_acme_external_success(
            authority,
            &mut candidate,
            &plan.view,
            &mut response,
        ) {
            erase_json(&mut response.body);
            return error;
        }
        candidate.schema = candidate.writer_schema();
        let records = match self.prepare_record_plan(&mut candidate) {
            Ok(records) => records,
            Err(error) => {
                erase_json(&mut response.body);
                return error;
            }
        };
        if let Err(error) = authority.bind_candidate(&candidate) {
            erase_json(&mut response.body);
            return error;
        }
        if let Err(error) = self.commit_record_plan_with_before_publish(
            &candidate,
            records,
            |_| authority.check_state(&candidate),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        ) {
            erase_json(&mut response.body);
            return error;
        }
        self.state = Some(self.install_committed_namespace_view(candidate));
        response
    }
}
