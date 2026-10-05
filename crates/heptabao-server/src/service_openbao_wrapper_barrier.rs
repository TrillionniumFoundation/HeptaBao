//! Explicit Wrapper barrier consumer with durable Recovery authority.
//! Filesystem and PostgreSQL consumers retain the genuine provider binding.

use std::fmt;
use std::path::Path;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use heptabao_openbao_grpc::{BridgeError, OpaqueBlobInfo};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::super::{
    Response, SealMetadata, bounded_u8_field, crypto, decode_initialization_secret,
};
#[cfg(target_os = "linux")]
use super::super::{Service, hex};
use super::{OpenBaoWrapperConfig, digest};

const MAX_BLOB: usize = 24 * 1024;
const MAX_ENCODED_ENVELOPE: usize = 60 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    schema: u32,
    seal_generation: u64,
    deployment_binding: String,
    blobinfo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<crate::auth::RecoveryPublic>,
}
impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WrapperBarrierEnvelope([REDACTED])")
    }
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.blobinfo.zeroize();
    }
}
impl Envelope {
    pub(in crate::service) fn recovery(&self) -> Option<&crate::auth::RecoveryPublic> {
        self.recovery.as_ref()
    }
    pub(crate) fn generation(&self) -> u64 {
        self.seal_generation
    }
    pub(crate) fn binding(&self) -> Result<[u8; 32], &'static str> {
        if self
            .deployment_binding
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        {
            return Err("invalid Wrapper deployment binding");
        }
        digest(&self.deployment_binding).map_err(|_| "invalid Wrapper deployment binding")
    }
    fn blob(&self) -> Result<OpaqueBlobInfo, &'static str> {
        if self.blobinfo.len() > MAX_BLOB * 4 / 3 {
            return Err("Wrapper BlobInfo exceeds seal bound");
        }
        let wire = Zeroizing::new(
            STANDARD
                .decode(&self.blobinfo)
                .map_err(|_| "invalid Wrapper BlobInfo encoding")?,
        );
        if wire.is_empty()
            || wire.len() > MAX_BLOB
            || STANDARD.encode(wire.as_slice()) != self.blobinfo
        {
            return Err("invalid canonical Wrapper BlobInfo");
        }
        let blob = OpaqueBlobInfo::from_protobuf(&wire).map_err(|_| "invalid Wrapper BlobInfo")?;
        if blob.ciphertext().is_empty() {
            return Err("empty Wrapper ciphertext");
        }
        Ok(blob)
    }
    pub(crate) fn decode(encoded: &str) -> Result<Self, &'static str> {
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_ENVELOPE {
            return Err("Wrapper seal envelope exceeds bound");
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| "invalid Wrapper seal encoding")?,
        );
        if STANDARD.encode(bytes.as_slice()) != encoded {
            return Err("noncanonical Wrapper seal encoding");
        }
        let envelope: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid Wrapper seal envelope")?;
        if envelope.seal_generation == 0
            || !matches!(
                (envelope.schema, envelope.recovery.as_ref()),
                (1, None) | (2, Some(_))
            )
        {
            return Err("unsupported Wrapper seal envelope");
        }
        if let Some(recovery) = &envelope.recovery {
            recovery
                .validate()
                .map_err(|_| "invalid public recovery configuration")?;
        }
        envelope.binding()?;
        envelope.blob()?;
        Ok(envelope)
    }
    #[cfg(target_os = "linux")]
    fn new(
        binding: [u8; 32],
        generation: u64,
        blob: &OpaqueBlobInfo,
    ) -> Result<Self, &'static str> {
        if blob.protobuf().len() > MAX_BLOB || blob.ciphertext().is_empty() {
            return Err("Wrapper seal BlobInfo exceeds bound or is empty");
        }
        Ok(Self {
            schema: 1,
            seal_generation: generation,
            deployment_binding: hex(&binding),
            blobinfo: STANDARD.encode(blob.protobuf()),
            recovery: None,
        })
    }

    fn encode(&self) -> Result<String, &'static str> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| "cannot encode Wrapper seal")?);
        let encoded = STANDARD.encode(bytes.as_slice());
        if encoded.len() > MAX_ENCODED_ENVELOPE {
            return Err("Wrapper seal envelope exceeds bound");
        }
        Ok(encoded)
    }
}

pub(crate) fn configuration_binding(
    config: &OpenBaoWrapperConfig,
    data_dir: &Path,
) -> Result<[u8; 32], BridgeError> {
    let mut bytes = b"heptabao.wrapper-barrier-deployment.v1\0".to_vec();
    bytes.extend_from_slice(&digest(&config.command_sha256)?);
    bytes.extend_from_slice(&digest(&config.configuration_sha256)?);
    if let (Some(path), Some(hash)) = (
        &config.soft_hsm_configuration_file,
        &config.soft_hsm_configuration_sha256,
    ) {
        bytes.extend_from_slice(b"\0softhsm-selector.v1\0");
        bytes.extend_from_slice(&digest(hash)?);
        bytes.extend_from_slice(&crypto::digest(path.as_os_str().as_encoded_bytes()));
    }
    // A store moved to another path requires a separately reviewed migration.
    bytes.extend_from_slice(&crypto::digest(data_dir.as_os_str().as_encoded_bytes()));
    Ok(crypto::digest(&bytes))
}

pub(in crate::service) struct PreparedMaterial {
    pub(in crate::service) seal: SealMetadata,
    pub(in crate::service) key: Zeroizing<[u8; 32]>,
    pub(in crate::service) deadline: Option<Instant>,
}

/// Admit deferred zero recovery or the implemented positive own-wire configuration.
/// The optional private nonce is a response-retrieval extension, never a share.
pub(in crate::service) fn validate_initialization_options(body: &Value) -> Result<bool, Response> {
    let object = body
        .as_object()
        .ok_or_else(|| Response::error(400, "initialization body must be an object"))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "secret_shares"
                | "secret_threshold"
                | "recovery_shares"
                | "recovery_threshold"
                | "recovery_nonce"
        )
    }) {
        return Err(Response::error(
            501,
            "Wrapper initialization options are unavailable",
        ));
    }
    let shares = bounded_u8_field(body, "secret_shares", 0)
        .map_err(|message| Response::error(400, message))?;
    let threshold = bounded_u8_field(body, "secret_threshold", 0)
        .map_err(|message| Response::error(400, message))?;
    if shares != 0 || threshold != 0 {
        return Err(Response::error(
            501,
            "Wrapper secret shares are unavailable",
        ));
    }
    let recovery_shares = bounded_u8_field(body, "recovery_shares", 0)
        .map_err(|message| Response::error(400, message))?;
    let recovery_threshold = bounded_u8_field(body, "recovery_threshold", 0)
        .map_err(|message| Response::error(400, message))?;
    if (recovery_shares == 0) != (recovery_threshold == 0) || recovery_threshold > recovery_shares {
        return Err(Response::error(
            400,
            "recovery shares and threshold must both be zero or a valid positive pair",
        ));
    }
    // bounded_u8_field enforces the full nonzero GF256 coordinate range; zero/zero stays deferred.
    if let Some(nonce) = body.get("recovery_nonce") {
        let _nonce =
            decode_initialization_secret(nonce).map_err(|message| Response::error(400, message))?;
    }
    Ok(body.get("recovery_nonce").is_some())
}

pub(in crate::service) fn recovery_public(
    seal: &SealMetadata,
) -> Result<Option<crate::auth::RecoveryPublic>, &'static str> {
    let envelope = Envelope::decode(&seal.wrapped_barrier_key)?;
    Ok(envelope.recovery.clone())
}
pub(in crate::service) fn same_provider_material(
    source: &SealMetadata,
    target: &SealMetadata,
) -> Result<bool, &'static str> {
    let source = Envelope::decode(&source.wrapped_barrier_key)?;
    let target = Envelope::decode(&target.wrapped_barrier_key)?;
    Ok(source.binding()? == target.binding()?
        && source.generation() == target.generation()
        && source.blob()?.protobuf() == target.blob()?.protobuf())
}
pub(in crate::service) fn seal_with_recovery(
    source: &SealMetadata,
    credential: &crate::auth::RecoveryCredential,
) -> Result<SealMetadata, &'static str> {
    if !source.is_wrapper() {
        return Err("recovery credential requires Wrapper source");
    }
    let mut envelope = Envelope::decode(&source.wrapped_barrier_key)?;
    envelope.schema = 2;
    envelope.recovery = Some(credential.public());
    let mut target = source.clone();
    target.schema = 3;
    target.secret_shares = credential.shares();
    target.secret_threshold = credential.threshold();
    target.wrapped_barrier_key = envelope.encode()?;
    target.validate()?;
    Ok(target)
}

#[cfg(any(target_os = "linux", test))]
fn initialization_activation_failure(response_retrieval: bool) -> &'static str {
    if response_retrieval {
        "Wrapper initialization activation unavailable; retrieve the prepared response with the same recovery nonce"
    } else {
        "Wrapper initialization activation unavailable; no response-retrieval credential was supplied"
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::super::load_seal_metadata;
    use super::super::{
        OpenBaoWrapperCompletion, OpenBaoWrapperOperationPlan, WrapperOperation, WrapperReply,
    };
    use super::*;
    use heptabao_openbao_grpc::protocol::wrapping::RpcOptions;
    use std::sync::Mutex;

    fn tighten_deadline(original: Option<Instant>, later: Option<Instant>) -> Option<Instant> {
        match (original, later) {
            (Some(original), Some(later)) => Some(original.min(later)),
            (original, later) => original.or(later),
        }
    }

    struct PrivateBody(Value);
    impl Drop for PrivateBody {
        fn drop(&mut self) {
            super::super::super::erase_json(&mut self.0);
        }
    }
    pub(crate) struct InitializationPlan {
        operation: Mutex<Option<OpenBaoWrapperOperationPlan>>,
        key: Zeroizing<[u8; 32]>,
        binding: [u8; 32],
        body: PrivateBody,
        response_retrieval: bool,
        publication_deadline: Option<Instant>,
        pending: Option<super::super::super::wrapper_ha::PendingInitialization>,
        join: Option<super::super::super::wrapper_ha::JoinAdmission>,
        join_reply: Option<(String, String, PrivateBody)>,
    }
    pub(crate) struct InitializationCompletion {
        operation: OpenBaoWrapperCompletion,
        publication_deadline: Option<Instant>,
    }
    #[cfg(test)]
    impl InitializationCompletion {
        pub(in crate::service) fn fixture_deadlines(&self) -> (Instant, Option<Instant>, bool) {
            (
                self.operation.deadline,
                self.publication_deadline,
                matches!(&self.operation.result, Ok(WrapperReply::Encrypted(_))),
            )
        }
    }
    impl InitializationPlan {
        pub(crate) fn execute(&self) -> Result<InitializationCompletion, BridgeError> {
            self.execute_with_deadline(None)
        }
        pub(crate) fn execute_before(
            &self,
            deadline: Instant,
        ) -> Result<InitializationCompletion, BridgeError> {
            self.execute_with_deadline(Some(deadline))
        }
        fn execute_with_deadline(
            &self,
            deadline: Option<Instant>,
        ) -> Result<InitializationCompletion, BridgeError> {
            let mut operation = self
                .operation
                .lock()
                .map_err(|_| BridgeError::LifecycleDenied)?
                .take()
                .ok_or(BridgeError::BeforeDispatch)?;
            let publication_deadline = tighten_deadline(self.publication_deadline, deadline);
            if let Some(deadline) = publication_deadline {
                operation.deadline = operation.deadline.min(deadline);
            }
            Ok(InitializationCompletion {
                operation: operation.execute(),
                publication_deadline,
            })
        }
    }
    pub(crate) struct ActivationPlan {
        operation: OpenBaoWrapperOperationPlan,
        seal: SealMetadata,
        publication_deadline: Option<Instant>,
    }
    pub(crate) struct ActivationCompletion {
        operation: OpenBaoWrapperCompletion,
        seal: SealMetadata,
        publication_deadline: Option<Instant>,
    }
    impl ActivationPlan {
        pub(crate) fn execute(self) -> ActivationCompletion {
            ActivationCompletion {
                operation: self.operation.execute(),
                seal: self.seal,
                publication_deadline: self.publication_deadline,
            }
        }
    }
    fn options(binding: [u8; 32], generation: u64) -> RpcOptions {
        let mut options = RpcOptions::default();
        options.with_disallow_env_vars = true;
        options.with_aad = b"heptabao.wrapper-barrier.v1\0".to_vec();
        options.with_aad.extend_from_slice(&binding);
        options
            .with_aad
            .extend_from_slice(&generation.to_be_bytes());
        options
    }
    impl Service {
        pub(crate) fn wrapper_barrier_selected(&self) -> bool {
            self.openbao_wrapper_owner
                .as_ref()
                .is_some_and(|owner| owner.barrier_binding.is_some())
        }
        pub(in crate::service) fn wrapper_barrier_binding(&self) -> Result<[u8; 32], BridgeError> {
            self.openbao_wrapper_owner
                .as_ref()
                .and_then(|owner| owner.barrier_binding)
                .ok_or(BridgeError::InvalidBinding)
        }
        pub(crate) fn prepare_wrapper_barrier_initialization(
            &self,
            body: &Value,
        ) -> Result<InitializationPlan, Response> {
            self.prepare_wrapper_barrier_initialization_inner(body, None, None)
        }
        pub(in crate::service) fn wrapper_barrier_initialization_claimed(&self) -> bool {
            self.openbao_wrapper_owner.as_ref().is_none_or(|owner| {
                owner
                    .barrier_initialization_claimed
                    .load(std::sync::atomic::Ordering::Acquire)
            })
        }
        pub(crate) fn prepare_wrapper_barrier_ha_join(
            &self,
            method: &str,
            path: &str,
            body: &Value,
        ) -> Result<Option<InitializationPlan>, Response> {
            if self.ha.is_none()
                || self.wrapper_barrier_initialization_claimed()
                || self.initialized()
                || self.seal.is_some()
                || self.state.is_some()
                || self.recovery_required
                || super::super::super::wrapper_ha::pending_exists(&self.data_dir).unwrap_or(true)
            {
                return Ok(None);
            }
            let Some(join) = self.prepare_ha_local_join()? else {
                return Ok(None);
            };
            self.prepare_wrapper_barrier_initialization_inner(
                &serde_json::json!({}),
                Some(join),
                Some((
                    method.to_owned(),
                    path.to_owned(),
                    PrivateBody(body.clone()),
                )),
            )
            .map(Some)
        }
        fn prepare_wrapper_barrier_initialization_inner(
            &self,
            body: &Value,
            join: Option<super::super::super::wrapper_ha::JoinAdmission>,
            join_reply: Option<(String, String, PrivateBody)>,
        ) -> Result<InitializationPlan, Response> {
            if self.recovery_required
                || self.initialized()
                || self.state.is_some()
                || self.seal.is_some()
                || self.durable_profile.is_some()
            {
                return Err(Response::error(
                    409,
                    "Wrapper initialization requires a fresh sealed store",
                ));
            }
            let pending = if self.ha.is_some()
                && super::super::super::wrapper_ha::pending_exists(&self.data_dir)
                    .map_err(|message| Response::error(503, message))?
            {
                Some(super::super::super::wrapper_ha::load_pending(
                    &self.data_dir,
                )?)
            } else {
                None
            };
            if self.ha.is_some() && pending.is_none() && join.is_none() {
                self.ha_initial_cluster()?;
            }
            let response_retrieval = validate_initialization_options(body)?;
            let binding = self
                .wrapper_barrier_binding()
                .map_err(|_| Response::error(503, "Wrapper deployment binding unavailable"))?;
            let key = Zeroizing::new(if pending.is_some() {
                [0; 32]
            } else {
                crypto::random::<32>()
                    .map_err(|_| Response::error(503, "barrier randomness unavailable"))?
            });
            let request = if let Some(pending) = &pending {
                let envelope = Envelope::decode(&pending.seal.wrapped_barrier_key)
                    .map_err(|message| Response::error(503, message))?;
                if envelope.binding().ok() != Some(binding)
                    || envelope.generation() != pending.seal.generation
                {
                    return Err(Response::error(
                        503,
                        "pending HA Wrapper deployment changed",
                    ));
                }
                let shares = bounded_u8_field(body, "recovery_shares", 0)
                    .map_err(|message| Response::error(400, message))?;
                let threshold = bounded_u8_field(body, "recovery_threshold", 0)
                    .map_err(|message| Response::error(400, message))?;
                if (shares, threshold)
                    != (pending.seal.secret_shares, pending.seal.secret_threshold)
                {
                    return Err(Response::error(
                        400,
                        "HA initialization recovery parameters differ",
                    ));
                }
                WrapperOperation::Decrypt {
                    blob: envelope
                        .blob()
                        .map_err(|message| Response::error(503, message))?,
                    options: options(binding, pending.seal.generation),
                }
            } else {
                WrapperOperation::Encrypt {
                    plaintext: Zeroizing::new(key.to_vec()),
                    options: options(binding, 1),
                }
            };
            let operation = self
                .prepare_openbao_wrapper_operation(request)
                .map_err(|_| Response::error(503, "Wrapper barrier admission failed"))?;
            // One candidate per owner generation. An abandoned/failed candidate is
            // never automatically retried against the same session.
            use std::sync::atomic::Ordering;
            if self.openbao_wrapper_owner.as_ref().is_none_or(|owner| {
                owner
                    .barrier_initialization_claimed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            }) {
                return Err(Response::error(
                    409,
                    "Wrapper initialization already claimed for this owner",
                ));
            }
            // The provider RPC remains bounded by its own timeout. Persistence
            // and activation retain the caller's original request deadline;
            // synchronous callers without one do not acquire a new clock.
            let publication_deadline = crate::request_deadline::current();
            Ok(InitializationPlan {
                operation: Mutex::new(Some(operation)),
                key,
                binding,
                body: PrivateBody(body.clone()),
                response_retrieval,
                publication_deadline,
                pending,
                join,
                join_reply,
            })
        }
        pub(crate) fn finalize_wrapper_barrier_initialization(
            &mut self,
            mut plan: InitializationPlan,
            completion: Result<InitializationCompletion, BridgeError>,
            now: u64,
            fingerprint: &str,
        ) -> Response {
            if self.initialized()
                || self.state.is_some()
                || self.recovery_required
                || self.seal.is_some()
                || self.durable_profile.is_some()
                || self.wrapper_barrier_binding().ok() != Some(plan.binding)
            {
                self.fence_openbao_wrapper();
                return Response::error(503, "Wrapper initialization owner or store changed");
            }
            // The executor can only shorten the original caller deadline. The
            // RPC completion still independently enforces its provider timeout.
            let deadline = tighten_deadline(
                completion
                    .as_ref()
                    .ok()
                    .and_then(|completion| completion.publication_deadline),
                tighten_deadline(
                    plan.publication_deadline,
                    crate::request_deadline::current(),
                ),
            );
            let result = completion
                .and_then(|completion| self.finish_openbao_wrapper_operation(completion.operation));
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                self.fence_openbao_wrapper();
                return Response::error(503, "Wrapper initialization caller deadline expired");
            }
            if let Some(pending) = plan.pending.take() {
                let key = match result {
                    Ok(WrapperReply::Decrypted(key)) if key.len() == 32 => key,
                    _ => {
                        self.fence_wrapper_barrier_delivery();
                        return Response::error(503, "HA pending Wrapper decryption unavailable");
                    }
                };
                let key = match <[u8; 32]>::try_from(key.as_slice()) {
                    Ok(key) => Zeroizing::new(key),
                    Err(_) => {
                        self.fence_wrapper_barrier_delivery();
                        return Response::error(503, "HA pending barrier key invalid");
                    }
                };
                if self
                    .audit_event(
                        "initialization-response-prepared",
                        fingerprint,
                        now,
                        Some(200),
                    )
                    .is_err()
                {
                    self.fence_wrapper_barrier_delivery();
                    return Response::error(503, "HA initialization response audit unavailable");
                }
                return match self.finish_pending_ha_initialization(
                    pending,
                    &key,
                    &plan.body.0,
                    deadline,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        self.fence_wrapper_barrier_delivery();
                        error
                    }
                };
            }
            let envelope = match result {
                Ok(WrapperReply::Encrypted(blob)) => {
                    Envelope::new(plan.binding, 1, &blob).and_then(|envelope| envelope.encode())
                }
                _ => Err("Wrapper initialization outcome unavailable"),
            };
            let encoded = match envelope {
                Ok(encoded) => encoded,
                Err(_) => {
                    self.fence_openbao_wrapper();
                    return Response::error(
                        503,
                        "Wrapper initialization failed; no active state published",
                    );
                }
            };
            let seal = SealMetadata {
                schema: 2,
                generation: 1,
                share_format: "wrapper-v1".into(),
                secret_shares: 0,
                secret_threshold: 0,
                wrapped_barrier_key: encoded,
            };
            let material = PreparedMaterial {
                seal,
                key: Zeroizing::new(*plan.key),
                deadline,
            };
            if let Some(join) = plan.join.take() {
                if let Err(error) = self.finish_ha_local_join(join, material) {
                    self.fence_wrapper_barrier_delivery();
                    return error;
                }
                let Some((method, path, mut body)) = plan.join_reply.take() else {
                    self.fence_wrapper_barrier_delivery();
                    return Response::error(503, "HA local join response binding absent");
                };
                return self.handle_at(&method, &path, "", "", std::mem::take(&mut body.0), now);
            }
            let (mut response, _) = self.initialize_with_wrapper_material(
                &plan.body.0,
                now,
                fingerprint,
                super::super::super::Service::import_postgres_initialization,
                Some(material),
            );
            if response.status != 200 {
                self.fence_openbao_wrapper();
                return response;
            }
            let initial_ha_identity = if self.ha.is_some() {
                match self.ha_initial_response_identity(&plan.key) {
                    Ok(identity) => Some(identity),
                    Err(error) => {
                        self.fence_wrapper_barrier_delivery();
                        super::super::super::erase_json(&mut response.body);
                        return error;
                    }
                }
            } else {
                None
            };
            let expected_seal = self.seal.clone();
            if deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || load_seal_metadata(&self.data_dir).ok().flatten() != expected_seal
                || self
                    .activate_barrier_with_deadline(&plan.key, deadline)
                    .is_err()
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || load_seal_metadata(&self.data_dir).ok().flatten() != expected_seal
                || initial_ha_identity.is_some_and(|expected| {
                    self.current_state_identity().ok() != Some(expected)
                        || self.verify_ha_state_identity(expected).is_err()
                })
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                self.fence_wrapper_barrier_delivery();
                super::super::super::erase_json(&mut response.body);
                return Response::error(
                    503,
                    initialization_activation_failure(plan.response_retrieval),
                );
            }
            response
        }
        pub(crate) fn prepare_wrapper_barrier_activation(
            &self,
        ) -> Result<Option<ActivationPlan>, String> {
            let Some(seal) = self.seal.as_ref().filter(|seal| seal.is_wrapper()) else {
                return Ok(None);
            };
            if self.state.is_some() || self.recovery_required {
                return Err("Wrapper startup requires sealed non-recovery state".into());
            }
            if load_seal_metadata(&self.data_dir).ok().flatten().as_ref() != Some(seal) {
                return Err("Wrapper startup seal changed".into());
            }
            let envelope = Envelope::decode(&seal.wrapped_barrier_key)?;
            let binding = self
                .wrapper_barrier_binding()
                .map_err(|_| "Wrapper deployment missing")?;
            if envelope.binding()? != binding || envelope.generation() != seal.generation {
                return Err("Wrapper deployment or seal generation changed".into());
            }
            let operation = self
                .prepare_openbao_wrapper_operation(WrapperOperation::Decrypt {
                    blob: envelope.blob()?,
                    options: options(binding, seal.generation),
                })
                .map_err(|_| "Wrapper startup admission failed")?;
            let publication_deadline = crate::request_deadline::current();
            Ok(Some(ActivationPlan {
                operation,
                seal: seal.clone(),
                publication_deadline,
            }))
        }
        pub(crate) fn finish_wrapper_barrier_activation(
            &mut self,
            completion: ActivationCompletion,
        ) -> Result<(), String> {
            if self.seal.as_ref() != Some(&completion.seal)
                || load_seal_metadata(&self.data_dir).ok().flatten().as_ref()
                    != Some(&completion.seal)
            {
                self.fence_wrapper_barrier_delivery();
                return Err("Wrapper startup seal changed before activation".into());
            }
            let result = self.finish_openbao_wrapper_operation(completion.operation);
            let key = match result {
                Ok(WrapperReply::Decrypted(key)) if key.len() == 32 => key,
                _ => {
                    self.fence_wrapper_barrier_delivery();
                    return Err("Wrapper startup key unavailable".into());
                }
            };
            let key = Zeroizing::new(
                <[u8; 32]>::try_from(key.as_slice())
                    .map_err(|_| "Wrapper barrier key length invalid")?,
            );
            let deadline = tighten_deadline(
                completion.publication_deadline,
                crate::request_deadline::current(),
            );
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                self.fence_wrapper_barrier_delivery();
                return Err("Wrapper activation deadline expired".into());
            }
            let admitted = match self.activate_barrier_with_deadline(&key, deadline) {
                Ok(admitted) => admitted,
                Err(_) => {
                    self.fence_wrapper_barrier_delivery();
                    return Err("Wrapper private recovery admission failed".into());
                }
            };
            if deadline.is_some_and(|deadline| Instant::now() >= deadline)
                || load_seal_metadata(&self.data_dir).ok().flatten() != admitted.0
                || !admitted.0.as_ref().is_some_and(SealMetadata::is_wrapper)
            {
                self.fence_wrapper_barrier_delivery();
                return Err("Wrapper barrier activation failed closed".into());
            }
            Ok(())
        }
        pub(in crate::service) fn fence_wrapper_barrier_delivery(&mut self) {
            self.fence_openbao_wrapper();
            self.namespace_runtime.clear();
            self.state = None;
            self.ha_activation = None;
            self.record_root = None;
            self.record_writes_since_gc = 0;
            self.ha_read_cache = None;
            self.durable = None;
            self.barrier_key = None;
            self.recovery_required = true;
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::{InitializationCompletion, InitializationPlan};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_and_positive_recovery_admission_share_the_optional_private_nonce_contract() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({"recovery_shares": 0, "recovery_threshold": 0}),
        ] {
            assert_eq!(
                validate_initialization_options(&body).map_err(|response| response.status),
                Ok(false)
            );
        }
        assert_eq!(
            validate_initialization_options(
                &serde_json::json!({"recovery_shares": 5, "recovery_threshold": 3})
            )
            .map_err(|response| response.status),
            Ok(false)
        );
        for body in [
            serde_json::json!({"recovery_shares": 0, "recovery_threshold": 1}),
            serde_json::json!({"recovery_shares": 1, "recovery_threshold": 0}),
            serde_json::json!({"recovery_shares": 2, "recovery_threshold": 3}),
            serde_json::json!({"recovery_shares": true}),
            serde_json::json!({"recovery_shares": -1}),
            serde_json::json!({"recovery_shares": 1.5}),
            serde_json::json!({"recovery_shares": 256}),
        ] {
            assert_eq!(
                validate_initialization_options(&body).map_err(|response| response.status),
                Err(400)
            );
        }
    }

    #[test]
    fn optional_response_retrieval_is_validated_and_never_invented() {
        let body = serde_json::json!({"recovery_nonce": "01".repeat(32), "recovery_shares": 0, "recovery_threshold": 0});
        assert_eq!(
            validate_initialization_options(&body).map_err(|response| response.status),
            Ok(true)
        );
        assert_eq!(
            validate_initialization_options(
                &serde_json::json!({"recovery_nonce": "00".repeat(32)})
            )
            .map_err(|response| response.status),
            Err(400)
        );
        assert_eq!(
            validate_initialization_options(&serde_json::json!({"recovery_nonce": null}))
                .map_err(|response| response.status),
            Err(400)
        );
        for option in ["recovery_pgp_keys", "pgp_keys", "root_token_pgp_key"] {
            let mut body = serde_json::json!({});
            body[option] = serde_json::json!([]);
            assert_eq!(
                validate_initialization_options(&body).map_err(|response| response.status),
                Err(501)
            );
        }
        assert!(initialization_activation_failure(true).contains("same recovery nonce"));
        assert!(
            initialization_activation_failure(false).contains("no response-retrieval credential")
        );
        assert!(
            !initialization_activation_failure(false).contains("retrieve the prepared response")
        );
    }

    fn encoded(blob: &[u8], binding: &str, generation: u64) -> Result<String, serde_json::Error> {
        Ok(STANDARD.encode(serde_json::to_vec(&serde_json::json!({
            "schema": 1, "seal_generation": generation,
            "deployment_binding": binding, "blobinfo": STANDARD.encode(blob),
        }))?))
    }

    #[test]
    fn persisted_blob_retains_unknown_fields_exactly() -> Result<(), Box<dyn std::error::Error>> {
        // Unknown nested KeyInfo field9 and outer BlobInfo field31 survive persistence.
        let wire = [
            0x0a, 2, 0xab, 0xcd, 0x12, 1, 8, 0x2a, 7, 0x1a, 1, b'k', 0x4a, 2, 9, 10, 0xfa, 1, 1, 11,
        ];
        let envelope = Envelope::decode(&encoded(&wire, &"11".repeat(32), 7)?)?;
        assert_eq!(envelope.blob()?.protobuf(), wire);
        assert_eq!(envelope.generation(), 7);
        assert_eq!(envelope.binding()?, [0x11; 32]);
        assert_eq!(
            format!("{envelope:?}"),
            "WrapperBarrierEnvelope([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn malformed_or_empty_external_envelopes_never_admit() -> Result<(), Box<dyn std::error::Error>>
    {
        let wire = [0x0a, 1, 7];
        for candidate in [
            encoded(&[], &"11".repeat(32), 1)?,
            encoded(&wire, &"00".repeat(32), 1)?,
            encoded(&wire, &"AA".repeat(32), 1)?,
            encoded(&wire, &"11".repeat(32), 0)?,
            encoded(&[0x0a, 8, 7], &"11".repeat(32), 1)?,
            "A".repeat(MAX_ENCODED_ENVELOPE + 1),
        ] {
            assert!(Envelope::decode(&candidate).is_err());
        }
        Ok(())
    }

    #[test]
    fn recovery_public_metadata_never_changes_provider_generation_or_opaque_blob()
    -> Result<(), Box<dyn std::error::Error>> {
        let wire = [0x0a, 2, 0xab, 0xcd, 0x12, 1, 8];
        let source = SealMetadata {
            schema: 2,
            generation: 7,
            share_format: "wrapper-v1".into(),
            secret_shares: 0,
            secret_threshold: 0,
            wrapped_barrier_key: encoded(&wire, &"11".repeat(32), 7)?,
        };
        let (credential, _) = crate::auth::RecoveryCredential::generate([9; 32], 4, 3, 2)
            .map_err(|_| std::io::Error::other("recovery generation failed"))?;
        let target = seal_with_recovery(&source, &credential).map_err(std::io::Error::other)?;
        assert_eq!(target.schema, 3);
        assert_eq!(target.generation, 7);
        assert_eq!(target.secret_shares, 3);
        assert_eq!(target.secret_threshold, 2);
        assert!(same_provider_material(&source, &target).map_err(std::io::Error::other)?);
        let public = recovery_public(&target)
            .map_err(std::io::Error::other)?
            .ok_or("missing recovery metadata")?;
        assert_eq!(public.generation, 4);
        assert!(target.validate().is_ok());
        let mut corrupt = target.clone();
        corrupt.secret_threshold = 1;
        assert!(corrupt.validate().is_err());
        Ok(())
    }
}
