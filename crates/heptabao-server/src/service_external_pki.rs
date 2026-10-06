//! Direct external PKI generation on the audited Service effect boundary.
//! Metadata and signing use one immutable deployment-enrolled provider route.
//! Whole-state fencing intentionally rejects even unrelated concurrent writes.
use super::plugin::{KmsKeyBinding, PluginResponseAuthority, SharedKmsPlugin};
use super::*;
use base64::engine::general_purpose::STANDARD as BASE64;
use heptabao_domain::SecretValue;
use heptabao_kms_contracts::KmsCapability;
use heptabao_plugin_host::PluginHostState;
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

thread_local! {
    static PUBLICATION_CLOCK: Cell<Option<(Duration, Instant)>> = const { Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    static POST_PUBLICATION_DELAY: Cell<Option<PublicationDelay>> = const { Cell::new(None) };
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum PublicationDelay {
    For(Duration),
    Until(Instant),
}

#[cfg(test)]
pub(super) struct PublicationDelayScope(Option<PublicationDelay>, PhantomData<Rc<()>>);
#[cfg(test)]
impl PublicationDelayScope {
    pub(super) fn enter(delay: Duration) -> Self {
        Self(
            POST_PUBLICATION_DELAY.with(|value| value.replace(Some(PublicationDelay::For(delay)))),
            PhantomData,
        )
    }

    pub(super) fn until(instant: Instant) -> Self {
        Self(
            POST_PUBLICATION_DELAY
                .with(|value| value.replace(Some(PublicationDelay::Until(instant)))),
            PhantomData,
        )
    }
}
#[cfg(test)]
impl Drop for PublicationDelayScope {
    fn drop(&mut self) {
        POST_PUBLICATION_DELAY.with(|value| value.set(self.0));
    }
}

#[cfg(test)]
pub(super) fn delay_after_publication_for_test() {
    if let Some(delay) = POST_PUBLICATION_DELAY.with(Cell::take) {
        std::thread::sleep(match delay {
            PublicationDelay::For(delay) => delay,
            PublicationDelay::Until(instant) => instant.saturating_duration_since(Instant::now()),
        });
    }
}

/// Retain the runtime's one admission timestamp, including its subsecond part.
/// Direct deterministic Service callers have no scope and retain integer time.
pub(super) struct PublicationClockScope {
    previous: Option<(Duration, Instant)>,
    _thread: PhantomData<Rc<()>>,
}
impl PublicationClockScope {
    pub(super) fn enter(unix: Duration, started: Instant) -> Self {
        let previous = PUBLICATION_CLOCK.with(|clock| clock.replace(Some((unix, started))));
        Self {
            previous,
            _thread: PhantomData,
        }
    }

    pub(super) fn explicit() -> Self {
        Self {
            previous: PUBLICATION_CLOCK.with(|clock| clock.replace(None)),
            _thread: PhantomData,
        }
    }
}
impl Drop for PublicationClockScope {
    fn drop(&mut self) {
        PUBLICATION_CLOCK.with(|clock| clock.set(self.previous));
    }
}

#[derive(Clone, Copy)]
struct PublicationClock(Option<(Duration, Instant)>);

/// Reuse the listener's trusted wall-time observation plus its original
/// monotonic anchor. Explicit-clock embedders without a scope retain exactly
/// their supplied integer time; no request payload can select this clock.
pub(super) fn public_origin_observation() -> Option<Duration> {
    PUBLICATION_CLOCK
        .with(Cell::get)
        .and_then(|(unix, started)| unix.checked_add(started.elapsed()))
}

pub(super) fn publication_now(logical_now: u64) -> u64 {
    PublicationClock::capture()
        .0
        .map_or(logical_now, |(unix, started)| {
            unix.saturating_add(started.elapsed())
                .as_secs()
                .max(logical_now)
        })
}

impl PublicationClock {
    fn capture() -> Self {
        Self(PUBLICATION_CLOCK.with(Cell::get))
    }
    fn remaining_at(self, expires: u64, logical_now: u64, elapsed: Duration) -> Duration {
        let now = self
            .0
            .map_or(Duration::from_secs(logical_now), |(unix, _)| {
                unix.saturating_add(elapsed)
                    .max(Duration::from_secs(logical_now))
            });
        Duration::from_secs(expires).saturating_sub(now)
    }
    fn remaining(self, expires: u64, logical_now: u64) -> Duration {
        self.remaining_at(
            expires,
            logical_now,
            self.0.map_or(Duration::ZERO, |(_, start)| start.elapsed()),
        )
    }
    fn rounded_seconds(remaining: Duration) -> u64 {
        remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() >= 500_000_000))
    }
}

struct RelatedPkiLane {
    request: SecretValue,
    template: Box<crate::engines::ExternalPkiTemplate>,
    sign_url: String,
    metadata_url: String,
}

pub(super) struct NoEffectPkiPlan {
    authority: PluginResponseAuthority,
    namespace: String,
    binding: crate::engines::PkiNoEffectBinding,
}

pub(super) struct ExternalPkiPlan {
    request: SecretValue,
    template: Box<crate::engines::ExternalPkiTemplate>,
    related: Vec<RelatedPkiLane>,
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
    // A read-only admission view cannot authorize an effect without the one
    // original affine Principal and its retained request clock. Rechecking it
    // stops provider effects when the actor or an actual ancestor expires.
    // Final publication separately checks the live state identity and authority.
    admitted_auth: CowOwner<AuthState>,
    deadline: Option<std::time::Instant>,
    publication_clock: PublicationClock,
    wrapping_ttl: Option<u64>,
    creation_path: String,
    // Captured only after our own durable publication. The original provider
    // stage identity and generation above are never replaced by this checkpoint.
    delivery_checkpoint: Option<(
        crate::state_record_root::StateIdentity,
        plugin::PublicationGeneration,
    )>,
}

struct SensitiveJson(Value);
impl Drop for SensitiveJson {
    fn drop(&mut self) {
        erase_json(&mut self.0);
    }
}

pub(crate) struct Observation {
    material: Box<crate::engines::ExternalPkiMaterial>,
    signatures: Vec<Zeroizing<Vec<u8>>>,
    related: Vec<Observation>,
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

pub(super) fn enrolled_pki_routes(
    outbound: &crate::outbound::Outbound,
    request: &SecretValue,
) -> Result<(String, String), Response> {
    let envelope =
        SensitiveJson(crate::auth::parse_strict_json(request.expose()).map_err(|_| unknown())?);
    let sign_url = envelope.0["url"].as_str().ok_or_else(unknown)?;
    let (origin, key) = sign_url.rsplit_once("/sign/").ok_or_else(unknown)?;
    let metadata_url = format!("{origin}/keys/{key}");
    for url in [sign_url, metadata_url.as_str()] {
        outbound.endpoint(url, "https").map_err(|_| {
            Response::error(
                503,
                "external PKI rejected before entry: HTTPS route is not deployment-enrolled",
            )
        })?;
        outbound
            .validate_external_transit_tls(
                url,
                envelope.0["tls_server_name"].as_str().unwrap_or(""),
                envelope.0["tls_ca_cert_bytes"].as_str().unwrap_or(""),
            )
            .map_err(|message| Response::error(503, message))?;
    }
    Ok((sign_url.into(), metadata_url))
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

    fn validate_private_leaf_time(&self) -> Result<(), Response> {
        self.authority.validate_live_auth(&self.admitted_auth)?;
        let time = self.authority.token_time()?;
        self.template
            .validate_private_leaf_time(time)
            .map_err(Response::from_engine_error)
    }

    fn enrollment_current(&self, outbound: &crate::outbound::Outbound) -> bool {
        [self.sign_url.as_str(), self.metadata_url.as_str()]
            .into_iter()
            .chain(
                self.related
                    .iter()
                    .flat_map(|lane| [lane.sign_url.as_str(), lane.metadata_url.as_str()]),
            )
            .all(|url| outbound.same_https_enrollment(&self.outbound, url))
    }

    pub(super) fn execute(&self) -> Result<Observation, Response> {
        let mut main = self.execute_lane(
            &self.request,
            &self.template,
            &self.sign_url,
            &self.metadata_url,
        )?;
        for lane in &self.related {
            main.related.push(self.execute_lane(
                &lane.request,
                &lane.template,
                &lane.sign_url,
                &lane.metadata_url,
            )?);
        }
        Ok(main)
    }

    fn execute_lane(
        &self,
        request: &SecretValue,
        template: &crate::engines::ExternalPkiTemplate,
        sign_url: &str,
        metadata_url: &str,
    ) -> Result<Observation, Response> {
        // Every lane borrows the same original response authority, actor clock,
        // absolute deadline and provider generation. No lane creates a new clock.
        self.validate_private_leaf_time()?;
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
        let envelope =
            SensitiveJson(crate::auth::parse_strict_json(request.expose()).map_err(|_| unknown())?);
        let token = envelope.0["token"].as_str().ok_or_else(unknown)?;
        let namespace = envelope.0["namespace"].as_str().ok_or_else(unknown)?;
        let version = envelope.0["remote_version"].as_u64().ok_or_else(unknown)?;
        let metadata = crypto_response(
            self.outbound
                .get_external_transit(metadata_url, token, namespace)
                .map_err(|message| Response::error(503, message))?,
        )?;
        let data = metadata
            .0
            .get("data")
            .and_then(Value::as_object)
            .ok_or_else(unknown)?;
        let kind = data
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(unknown)?;
        if data.get("supports_signing").and_then(Value::as_bool) != Some(true)
            || data.get("latest_version").and_then(Value::as_u64).is_none()
        {
            return Err(unknown());
        }
        // Pinned 2.7 direct generation rejects an old fixed mapping after the
        // provider rotates; it does not silently bind a fresh issuer to latest.
        if data.get("latest_version").and_then(Value::as_u64) != Some(version) {
            return Err(Response::error(
                if template.is_consumption() { 500 } else { 400 },
                "external PKI provider version changed",
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
        let public = crate::engines::ExternalPkiPublicKey::from_metadata(kind, public_text)
            .map_err(|cause| Response::error(cause.status, &cause.message))?;
        let material = template
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
        self.validate_private_leaf_time()?;
        let mut signatures = Vec::with_capacity(material.tbs_parts().count());
        for (index, tbs) in material.tbs_parts().enumerate() {
            self.validate_private_leaf_time()?;
            if self.authority.deadline_expired() || !self.provider_host_current() {
                return Err(Response::error(
                    503,
                    "external PKI withheld between signing effects; remote outcome unknown; no blind retry",
                ));
            }
            let input = material
                .signing_input(tbs)
                .map_err(|cause| Response::error(cause.status, &cause.message))?;
            let mut body = SensitiveJson(
                json!({"input":BASE64.encode(input),"key_version":version_key,
            "prehashed":material.hash_algorithm().is_some(),"signature_algorithm":material.signature_algorithm()}),
            );
            if material.signature_algorithm() == "pss" {
                body.0["salt_length"] = json!("hash");
            }
            if let Some(hash) = material.hash_algorithm() {
                body.0["hash_algorithm"] = json!(hash);
            }
            let signed = crypto_response(
                self.outbound
                    .put_external_transit(sign_url, token, namespace, &body.0)
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
            if text.is_empty() || text.len() > material.signature_size_bound().div_ceil(3) * 4 {
                return Err(unknown());
            }
            let signature = Zeroizing::new(BASE64.decode(text).map_err(|_| unknown())?);
            if BASE64.encode(&*signature) != text {
                return Err(unknown());
            }
            material
                .verify_at(index, &signature)
                .map_err(|cause| Response::error(cause.status, &cause.message))?;
            signatures.push(signature);
        }
        self.validate_private_leaf_time()?;
        Ok(Observation {
            material: Box::new(material),
            signatures,
            related: Vec::new(),
        })
    }
}

impl Service {
    fn complete_external_pki_no_effect_publication(
        &mut self,
        admitted: &State,
        principal: Principal,
        request: &RequestView<'_>,
        capability: &'static str,
        binding: crate::engines::PkiNoEffectBinding,
        mut result: crate::engines::EngineResponse,
    ) -> Response {
        if result.mutated {
            return Response::error(503, "PKI no-effect result unexpectedly changed state");
        }
        let mut authority = PluginResponseAuthority::new(
            principal,
            admitted,
            request,
            capability,
            false,
            &self.unseal_nonce,
        )
        .with_time_floor(admitted.engines.lease_clock());
        let mut response = Response {
            response_headers: Default::default(),
            consistency_index: None,
            status: result.status,
            body: std::mem::take(&mut result.body),
        };
        if let Err(error) = self.validate_plugin_response(&mut authority) {
            erase_json(&mut response.body);
            return error;
        }
        let Some(mut candidate) = self.state.clone() else {
            erase_json(&mut response.body);
            return unknown();
        };
        if !candidate
            .engines
            .external_pki_no_effect_current(request.namespace, &binding)
        {
            erase_json(&mut response.body);
            return Response::error(503, "PKI no-effect owner changed before publication");
        }
        let observed = match authority.observe_candidate_time(&mut candidate) {
            Ok(time) => time,
            Err(error) => {
                erase_json(&mut response.body);
                return error;
            }
        };
        if let Some(ttl) = request.wrap_ttl_seconds.filter(|ttl| *ttl > 0) {
            let mut wrapped = match candidate.auth.wrap_response(
                request.namespace,
                request.path,
                ttl,
                &response.body,
                observed.seconds(),
            ) {
                Ok(value) => value,
                Err(error) => {
                    erase_json(&mut response.body);
                    return Response::error(error.status, &error.message);
                }
            };
            erase_json(&mut response.body);
            response.status = wrapped.status;
            response.body = std::mem::take(&mut wrapped.body);
        }
        candidate.schema = candidate.writer_schema();
        if let Err(error) = candidate.validate_format() {
            erase_json(&mut response.body);
            return error;
        }
        let record = match self.prepare_record_plan(&mut candidate) {
            Ok(value) => value,
            Err(error) => {
                erase_json(&mut response.body);
                return error;
            }
        };
        if let Err(error) = self
            .validate_plugin_response(&mut authority)
            .and_then(|()| authority.validate_live_auth(&candidate.auth))
        {
            erase_json(&mut response.body);
            return error;
        }
        if !self.state.as_ref().is_some_and(|state| {
            state
                .engines
                .external_pki_no_effect_current(request.namespace, &binding)
        }) || !candidate
            .engines
            .external_pki_no_effect_current(request.namespace, &binding)
        {
            erase_json(&mut response.body);
            return Response::error(503, "PKI no-effect owner changed before commit");
        }
        if let Err(error) = self.commit_record_plan_with_before_publish(
            &candidate,
            record,
            |auth| authority.validate_live_auth(auth),
            #[cfg(all(feature = "fixture-native-restore-faults", target_os = "linux"))]
            None,
        ) {
            erase_json(&mut response.body);
            return error;
        }
        self.state = Some(candidate);
        // The original moved actor, request time and exact unchanged PKI receipt
        // remain held through the response audit and final delivery check.
        self.pending_external_pki_no_effect = Some(NoEffectPkiPlan {
            authority,
            namespace: request.namespace.to_owned(),
            binding,
        });
        response
    }

    pub(super) fn complete_pending_external_pki_no_effect_delivery(
        &mut self,
        expected: bool,
        mut response: Response,
        fingerprint: &str,
    ) -> Response {
        let mut plan = match (expected, self.pending_external_pki_no_effect.take()) {
            (true, Some(plan)) => plan,
            (false, None) => return response,
            _ => {
                erase_json(&mut response.body);
                response.response_headers = Default::default();
                response.consistency_index = None;
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(503, "PKI no-effect delivery capsule was lost");
            }
        };
        if response.status >= 300 {
            return response;
        }
        let checked = self
            .validate_plugin_response(&mut plan.authority)
            .and_then(|()| {
                let state = self.state.as_ref().ok_or_else(unknown)?;
                plan.authority.validate_live_auth(&state.auth)?;
                if !state
                    .engines
                    .external_pki_no_effect_current(&plan.namespace, &plan.binding)
                {
                    return Err(Response::error(
                        503,
                        "PKI no-effect owner changed before delivery",
                    ));
                }
                Ok(())
            });
        if let Err(error) = checked {
            erase_json(&mut response.body);
            response.response_headers = Default::default();
            response.consistency_index = None;
            if self
                .audit_event(
                    "external-pki-no-effect-delivery-veto",
                    fingerprint,
                    plan.authority.now(),
                    Some(error.status),
                )
                .is_err()
            {
                crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
                self.recovery_required = true;
                self.ha_activation = None;
                return Response::error(
                    503,
                    "PKI no-effect delivery veto audit failed; recovery required",
                );
            }
            return error;
        }
        response
    }

    pub(super) fn stage_external_pki(
        &mut self,
        state: &State,
        principal: Option<Principal>,
        request: &RequestView<'_>,
    ) -> Response {
        let Some(principal) = principal else {
            return Response::error(403, "permission denied");
        };
        let Some(capability) =
            state
                .engines
                .required_capability(request.namespace, request.method, request.path)
        else {
            return Response::error(404, "PKI route not found");
        };
        let time = match request.token_time().and_then(|time| {
            time.with_seconds_floor(state.engines.lease_clock())
                .map_err(|_| Response::error(503, "trusted token clock is unavailable"))
        }) {
            Ok(time) => state.auth.token_api_observed_time(time),
            Err(error) => return error,
        };
        if let Err(cause) = state.auth.authorize_request_observed(
            &principal,
            request.namespace,
            request.path,
            capability,
            time,
        ) {
            return Response::error(cause.status, &cause.message);
        }
        if self.pending_external_pki.is_some() {
            return Response::error(503, "another external PKI generation is pending");
        }
        let owner = if state
            .engines
            .is_pki_issue_route(request.namespace, request.path)
            || state
                .engines
                .is_pki_acme_operator_revoke_route(request.namespace, request.path)
        {
            match state
                .auth
                .typed_lease_issuer_observed(&principal, request.namespace, time)
            {
                Ok(owner) => Some(owner),
                Err(cause) => return Response::error(cause.status, &cause.message),
            }
        } else {
            None
        };
        let identity_values =
            match Self::pki_identity_values(state, &principal, request.namespace, request.path) {
                Ok(values) => values,
                Err(cause) => return cause,
            };
        match state.engines.prepare_external_pki_no_effect(
            request.namespace,
            request.method,
            request.path,
            request.body,
            crate::engines::PkiRequestContext {
                owner: owner.as_ref(),
                time,
                clock: request.token_clock,
                identity_templates: None,
            },
        ) {
            Ok(Some((binding, response))) => {
                return self.complete_external_pki_no_effect_publication(
                    state, principal, request, capability, binding, response,
                );
            }
            Ok(None) => {}
            Err(cause) => return Response::from_engine_error(cause),
        }
        let plan = match state.engines.prepare_external_pki(
            request.namespace,
            request.method,
            request.path,
            request.body,
            crate::engines::PkiRequestContext {
                owner: owner.as_ref(),
                time,
                clock: request.token_clock,
                identity_templates: Some(&identity_values),
            },
        ) {
            Ok(Some(plan)) => plan,
            Ok(None) if request.wrap_ttl_seconds.is_some_and(|ttl| ttl > 0) => {
                return Response::error(
                    501,
                    "external PKI no-effect response wrapping is not implemented",
                );
            }
            Ok(None)
                if state
                    .engines
                    .is_pki_acme_operator_revoke_route(request.namespace, request.path) =>
            {
                // A previously revoked or already expired ACME certificate has
                // a native no-effect result. Keep the same admitted actor; this
                // branch cannot enter a new local or provider signing effect.
                let mut engines = state.engines.clone();
                return match engines.handle_service_pki_operator_revoke(
                    request.namespace,
                    request.method,
                    request.path,
                    request.body,
                    crate::engines::PkiRequestContext {
                        owner: owner.as_ref(),
                        time,
                        clock: request.token_clock,
                        identity_templates: None,
                    },
                    || {
                        Err(crate::engines::EngineError {
                            status: 503,
                            message: "no-effect revocation cannot enter signing".into(),
                        })
                    },
                ) {
                    Ok(mut response) if !response.mutated => Response {
                        response_headers: Default::default(),
                        consistency_index: None,
                        status: response.status,
                        body: std::mem::take(&mut response.body),
                    },
                    Ok(_) => Response::error(503, "no-effect revocation changed state"),
                    Err(cause) => Response::from_engine_error(cause),
                };
            }
            Ok(None) => return Response::error(404, "external PKI route not found"),
            Err(cause) => return Response::from_engine_error(cause),
        };
        let (sign_url, metadata_url) = match enrolled_pki_routes(&self.outbound, &plan.request) {
            Ok(routes) => routes,
            Err(cause) => return cause,
        };
        let related = match plan
            .related
            .into_iter()
            .map(|lane| {
                let (sign_url, metadata_url) = enrolled_pki_routes(&self.outbound, &lane.request)?;
                Ok(RelatedPkiLane {
                    request: lane.request,
                    template: Box::new(lane.template),
                    sign_url,
                    metadata_url,
                })
            })
            .collect::<Result<Vec<_>, Response>>()
        {
            Ok(lanes) => lanes,
            Err(cause) => return cause,
        };
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
            template: Box::new(plan.template),
            related,
            namespace: request.namespace.into(),
            mount: plan.mount,
            mount_incarnation: plan.mount_incarnation,
            sign_url,
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
            )
            .with_time_floor(state.engines.lease_clock()),
            admitted_auth: state.auth.clone(),
            deadline: crate::request_deadline::current(),
            publication_clock: PublicationClock::capture(),
            wrapping_ttl: request.wrap_ttl_seconds.filter(|ttl| *ttl > 0),
            creation_path: request.path.into(),
            delivery_checkpoint: None,
        });
        Response::error(500, "external PKI generation was not dispatched")
    }

    pub(super) fn finalize_external_pki(
        &mut self,
        plan: &mut ExternalPkiPlan,
        result: Result<Observation, Response>,
    ) -> Response {
        let observation = match result {
            Ok(value) => value,
            Err(cause) => return cause,
        };
        if observation.related.len() != plan.related.len() {
            return unknown();
        }
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
            || !plan.enrollment_current(&self.outbound)
        {
            return Response::error(
                503,
                "external PKI result withheld after authority/state changed; remote outcome unknown; no blind retry",
            );
        }
        let time = match plan.authority.token_time() {
            Ok(time) => self
                .state
                .as_ref()
                .map_or(time, |state| state.auth.token_api_observed_time(time)),
            Err(error) => return error,
        };
        if let Err(cause) = plan.template.validate_private_leaf_time(time) {
            return Response::from_engine_error(cause);
        }
        let now = if time.exact().is_some() {
            time.seconds()
        } else {
            plan.authority.now()
        };
        if plan
            .template
            .leaf_lease_window()
            .is_some_and(|(expires, _)| plan.publication_clock.remaining(expires, now).is_zero())
        {
            return Response::error(403, "external PKI leaf validity window expired");
        }
        if let Some(owner) = plan.template.leaf_owner() {
            let live = self.state.as_ref().and_then(|state| {
                state
                    .auth
                    .resolve_lease_owner_observed(owner, &plan.namespace, time)
            });
            let active = live.as_ref().is_some_and(|owner| {
                owner.entity_id.as_ref().is_none_or(|id| {
                    self.state.as_ref().is_some_and(|state| {
                        state
                            .engines
                            .identity_projection(&plan.namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
            });
            if !active {
                return Response::error(403, "external PKI leaf issuer is no longer live");
            }
        }
        let Some(mut candidate) = self.state.clone() else {
            return unknown();
        };
        if let Err(error) = plan.authority.observe_candidate_time(&mut candidate) {
            return error;
        }
        let mut response = match candidate.engines.publish_external_pki(
            &plan.namespace,
            &plan.mount,
            plan.mount_incarnation,
            *observation.material,
            &observation.signatures,
            now,
        ) {
            Ok(value) => value,
            Err(cause) => return Response::from_engine_error(cause),
        };
        for related in observation.related {
            if let Err(cause) = candidate.engines.publish_external_pki(
                &plan.namespace,
                &plan.mount,
                plan.mount_incarnation,
                *related.material,
                &related.signatures,
                now,
            ) {
                erase_json(&mut response.body);
                return Response::from_engine_error(cause);
            }
        }
        if let Some(ttl) = plan.wrapping_ttl {
            // The original response and private wrapper are one candidate.
            // The retained actor, provider and final delivery capsule stay held.
            // Completion may run after the listener's scope has left the thread.
            // Re-enter only its retained wall/monotonic anchor for the public
            // creation stamp; this does not renew any private authority or TTL.
            let _origin_scope = match plan.publication_clock.0 {
                Some((unix, started)) => PublicationClockScope::enter(unix, started),
                None => PublicationClockScope::explicit(),
            };
            if let Some((expires, leased)) = plan.template.leaf_lease_window() {
                let remaining = plan.publication_clock.remaining(expires, now);
                if remaining.is_zero() {
                    erase_json(&mut response.body);
                    return Response::error(403, "external PKI leaf expired before wrapping");
                }
                response.body["lease_duration"] = json!(if leased {
                    PublicationClock::rounded_seconds(remaining)
                } else {
                    0
                });
            }
            let mut wrapped = match candidate.auth.wrap_response(
                &plan.namespace,
                &plan.creation_path,
                ttl,
                &response.body,
                now,
            ) {
                Ok(value) => value,
                Err(cause) => {
                    erase_json(&mut response.body);
                    return Response::error(cause.status, &cause.message);
                }
            };
            erase_json(&mut response.body);
            response.status = wrapped.status;
            response.body = std::mem::take(&mut wrapped.body);
        }
        candidate.schema = candidate.writer_schema();
        if let Err(cause) = candidate.validate_format() {
            erase_json(&mut response.body);
            return cause;
        }
        let record_plan = match self.prepare_record_plan(&mut candidate) {
            Ok(value) => value,
            Err(cause) => {
                erase_json(&mut response.body);
                return cause;
            }
        };
        if let Err(cause) = self.commit_record_plan(&candidate, record_plan) {
            erase_json(&mut response.body);
            return cause;
        }
        self.state = Some(candidate);
        plan.delivery_checkpoint = match (
            self.current_state_identity(),
            self.external_effect_generation(),
        ) {
            (Ok(identity), Ok(generation)) => Some((identity, generation)),
            _ => {
                erase_json(&mut response.body);
                return unknown();
            }
        };
        #[cfg(test)]
        delay_after_publication_for_test();
        Response {
            response_headers: Default::default(),
            consistency_index: None,
            status: response.status,
            body: std::mem::take(&mut response.body),
        }
    }

    // Only the writer can mint this consumed clock-only receipt. It advances
    // our own completed publication checkpoint, never the original provider
    // admission identity/generation or actor clock. An intervening state write
    // fails the exact predecessor match and stays fenced at final delivery.
    pub(super) fn audit_external_pki_response(
        &mut self,
        plan: &mut ExternalPkiPlan,
        fingerprint: &str,
        request_clock: (u64, Option<crate::auth::RequestClock>),
        response: Response,
        after_audit: impl FnOnce(),
    ) -> Response {
        let (response, receipt) = self.audit_completed_response_with_clock_receipt(
            fingerprint,
            request_clock,
            response,
            after_audit,
            true,
        );
        if (200..300).contains(&response.status)
            && let Some(receipt) = receipt
        {
            receipt.advance(&mut plan.delivery_checkpoint);
        }
        response
    }

    /// The original response audit and consistency stamp may block after the
    /// encrypted commit. Keep the original plan until this last delivery fence:
    /// publication can remain durable while its private response is withheld.
    pub(super) fn complete_external_pki_delivery(
        &mut self,
        plan: &mut ExternalPkiPlan,
        response: Response,
        fingerprint: &str,
    ) -> Response {
        let planned_success = (200..300).contains(&response.status);
        let mut response = self.external_pki_delivery_gate(plan, response);
        if planned_success
            && !(200..300).contains(&response.status)
            && self
                .audit_event(
                    "external-pki-delivery-veto",
                    fingerprint,
                    plan.authority.now(),
                    Some(response.status),
                )
                .is_err()
        {
            // The private body has already been erased by the gate. This final
            // negative observation contains only a status and the original path
            // digest; its failure cannot grant delivery or initiate another effect.
            erase_json(&mut response.body);
            crate::service::openbao_wrapper::fence(&self.openbao_wrapper_owner);
            self.recovery_required = true;
            self.ha_activation = None;
            return Response::error(
                503,
                "external PKI delivery veto audit failed; committed outcome requires recovery; no blind retry",
            );
        }
        response
    }

    fn external_pki_delivery_gate(
        &mut self,
        plan: &mut ExternalPkiPlan,
        mut response: Response,
    ) -> Response {
        if !(200..300).contains(&response.status) {
            return response;
        }
        if let Err(cause) = self.validate_plugin_response(&mut plan.authority) {
            erase_json(&mut response.body);
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
                    erase_json(&mut response.body);
                    return Response::error(503, "external PKI provider host busy before delivery");
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
        if !provider_current
            || !checkpoint_current
            || !self.state.as_ref().is_some_and(|state| {
                state.engines.external_pki_mount_current(
                    &plan.namespace,
                    &plan.mount,
                    plan.mount_incarnation,
                )
            })
            || !plan.enrollment_current(&self.outbound)
            || plan.authority.deadline_expired()
        {
            erase_json(&mut response.body);
            return Response::error(
                503,
                "external PKI committed response withheld by delivery fence; public readback required; no blind retry",
            );
        }
        let time = match plan.authority.token_time() {
            Ok(time) => self
                .state
                .as_ref()
                .map_or(time, |state| state.auth.token_api_observed_time(time)),
            Err(error) => {
                erase_json(&mut response.body);
                return error;
            }
        };
        if let Err(cause) = plan.template.validate_private_leaf_time(time) {
            erase_json(&mut response.body);
            return Response::from_engine_error(cause);
        }
        let now = if time.exact().is_some() {
            time.seconds()
        } else {
            plan.authority.now()
        };
        if let Some(owner) = plan.template.leaf_owner() {
            let live = self.state.as_ref().and_then(|state| {
                state
                    .auth
                    .resolve_lease_owner_observed(owner, &plan.namespace, time)
            });
            let active = live.as_ref().is_some_and(|owner| {
                owner.entity_id.as_ref().is_none_or(|id| {
                    self.state.as_ref().is_some_and(|state| {
                        state
                            .engines
                            .identity_projection(&plan.namespace, id)
                            .is_ok_and(|projection| !projection.disabled)
                    })
                })
            });
            if !active {
                erase_json(&mut response.body);
                return Response::error(403, "external PKI committed leaf owner is no longer live");
            }
        }
        // Sample after every potentially blocking publication/audit/HA check.
        // The admission fraction and monotonic start are immutable; the current
        // authority clock can only raise that time floor, never renew validity.
        if let Some((expires, leased)) = plan.template.leaf_lease_window() {
            let remaining = plan.publication_clock.remaining(expires, now);
            if remaining.is_zero() {
                erase_json(&mut response.body);
                return Response::error(
                    403,
                    "external PKI committed leaf expired before delivery; no blind retry",
                );
            }
            if plan.wrapping_ttl.is_none() {
                response.body["lease_duration"] = json!(if leased {
                    PublicationClock::rounded_seconds(remaining)
                } else {
                    0
                });
            }
        }
        response
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn external_pki270_publication_clock_rounds_remaining_cert_validity_and_keeps_logical_floor() {
        let clock =
            |millis| PublicationClock(Some((Duration::from_millis(millis), Instant::now())));
        assert_eq!(
            PublicationClock::rounded_seconds(clock(100_250).remaining_at(
                700,
                100,
                Duration::ZERO
            )),
            600
        );
        assert_eq!(
            PublicationClock::rounded_seconds(clock(100_750).remaining_at(
                700,
                100,
                Duration::ZERO
            )),
            599
        );
        assert_eq!(
            PublicationClock::rounded_seconds(clock(100_250).remaining_at(
                700,
                100,
                Duration::from_millis(1600)
            )),
            598
        );
        assert_eq!(
            clock(100_250).remaining_at(700, 150, Duration::ZERO),
            Duration::from_secs(550)
        );
        assert_eq!(
            clock(100_250).remaining_at(700, 100, Duration::from_secs(600)),
            Duration::ZERO
        );
        assert_eq!(
            PublicationClock(None).remaining_at(700, 100, Duration::ZERO),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn external_pki270_publication_clock_scope_restores_and_does_not_cross_threads() {
        assert!(PublicationClock::capture().0.is_none());
        let started = Instant::now();
        let outer = PublicationClockScope::enter(Duration::from_millis(100_250), started);
        let unwind = std::panic::catch_unwind(|| {
            let _inner = PublicationClockScope::enter(Duration::from_millis(100_750), started);
            assert_eq!(
                PublicationClock::capture().0.map(|(unix, _)| unix),
                Some(Duration::from_millis(100_750))
            );
            std::panic::resume_unwind(Box::new("publication clock unwind"));
        });
        assert!(unwind.is_err());
        assert_eq!(
            PublicationClock::capture().0.map(|(unix, _)| unix),
            Some(Duration::from_millis(100_250))
        );
        let isolated = std::thread::spawn(|| PublicationClock::capture().0.is_none()).join();
        assert!(matches!(isolated, Ok(true)));
        drop(outer);
        assert!(PublicationClock::capture().0.is_none());
    }
}
