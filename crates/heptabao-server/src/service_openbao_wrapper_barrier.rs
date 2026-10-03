//! Explicit Wrapper barrier consumer proposal. No local-unseal fallback.
//! This first opt-in profile omits recovery-key, rekey, migration and PG init.

use std::fmt;
use std::path::Path;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use heptabao_openbao_grpc::{BridgeError, OpaqueBlobInfo};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::super::{SealMetadata, crypto};
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
        if envelope.schema != 1 || envelope.seal_generation == 0 {
            return Err("unsupported Wrapper seal envelope");
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
        })
    }
    #[cfg(target_os = "linux")]
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
    pub(in crate::service) deadline: Instant,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::super::{
        Response, bounded_u8_field, decode_initialization_secret, load_seal_metadata,
    };
    use super::super::{
        OpenBaoWrapperCompletion, OpenBaoWrapperOperationPlan, WrapperOperation, WrapperReply,
    };
    use super::*;
    use heptabao_openbao_grpc::protocol::wrapping::RpcOptions;
    use serde_json::Value;
    use std::sync::Mutex;

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
        deadline: Instant,
    }
    impl InitializationPlan {
        pub(crate) fn deadline(&self) -> Instant {
            self.deadline
        }
        pub(crate) fn execute_before(
            &self,
            deadline: Instant,
        ) -> Result<OpenBaoWrapperCompletion, BridgeError> {
            let mut operation = self
                .operation
                .lock()
                .map_err(|_| BridgeError::LifecycleDenied)?
                .take()
                .ok_or(BridgeError::BeforeDispatch)?;
            operation.deadline = operation.deadline.min(deadline);
            Ok(operation.execute())
        }
    }
    pub(crate) struct ActivationPlan {
        operation: OpenBaoWrapperOperationPlan,
        seal: SealMetadata,
        deadline: Instant,
    }
    pub(crate) struct ActivationCompletion {
        operation: OpenBaoWrapperCompletion,
        seal: SealMetadata,
        deadline: Instant,
    }
    impl ActivationPlan {
        pub(crate) fn execute(self) -> ActivationCompletion {
            ActivationCompletion {
                operation: self.operation.execute(),
                seal: self.seal,
                deadline: self.deadline,
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
        fn wrapper_barrier_binding(&self) -> Result<[u8; 32], BridgeError> {
            self.openbao_wrapper_owner
                .as_ref()
                .and_then(|owner| owner.barrier_binding)
                .ok_or(BridgeError::InvalidBinding)
        }
        pub(crate) fn prepare_wrapper_barrier_initialization(
            &self,
            body: &Value,
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
            if self.ha.is_some() || self.postgres_durable.is_some() {
                return Err(Response::error(
                    501,
                    "Wrapper HA/PostgreSQL initialization requires a supported consumer",
                ));
            }
            if body.as_object().is_none_or(|body| {
                body.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "secret_shares" | "secret_threshold" | "recovery_nonce"
                    )
                })
            }) || bounded_u8_field(body, "secret_shares", 0).ok() != Some(0)
                || bounded_u8_field(body, "secret_threshold", 0).ok() != Some(0)
            {
                return Err(Response::error(
                    501,
                    "Wrapper recovery shares and initialization options are unavailable",
                ));
            }
            // Preserve an authenticated response-retrieval channel for lost publication replies.
            // This deployment extension is not an OpenBao recovery-key implementation.
            let _nonce =
                decode_initialization_secret(body.get("recovery_nonce").ok_or_else(|| {
                    Response::error(400, "recovery_nonce is required for Wrapper initialization")
                })?)
                .map_err(|_| Response::error(400, "invalid initialization recovery nonce"))?;
            let binding = self
                .wrapper_barrier_binding()
                .map_err(|_| Response::error(503, "Wrapper deployment binding unavailable"))?;
            let key = Zeroizing::new(
                crypto::random::<32>()
                    .map_err(|_| Response::error(503, "barrier randomness unavailable"))?,
            );
            let operation = self
                .prepare_openbao_wrapper_operation(WrapperOperation::Encrypt {
                    plaintext: Zeroizing::new(key.to_vec()),
                    options: options(binding, 1),
                })
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
            let deadline = operation.deadline;
            Ok(InitializationPlan {
                operation: Mutex::new(Some(operation)),
                key,
                binding,
                body: PrivateBody(body.clone()),
                deadline,
            })
        }
        pub(crate) fn finalize_wrapper_barrier_initialization(
            &mut self,
            plan: InitializationPlan,
            completion: Result<OpenBaoWrapperCompletion, BridgeError>,
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
            // The HTTP executor may tighten the prepared deadline. Its actual
            // completion retains that effective deadline for every later gate.
            let deadline = completion
                .as_ref()
                .map_or(plan.deadline, |completion| completion.deadline)
                .min(plan.deadline);
            let result =
                completion.and_then(|completion| self.finish_openbao_wrapper_operation(completion));
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
            let (mut response, _) = self.initialize_with_wrapper_material(
                &plan.body.0,
                now,
                fingerprint,
                |_, _| Err(super::super::super::BackendError::Unsupported),
                Some(material),
            );
            if response.status != 200 {
                self.fence_openbao_wrapper();
                return response;
            }
            let expected_seal = self.seal.clone();
            if Instant::now() >= deadline
                || load_seal_metadata(&self.data_dir).ok().flatten() != expected_seal
                || self.activate_barrier(&plan.key).is_err()
                || Instant::now() >= deadline
                || load_seal_metadata(&self.data_dir).ok().flatten() != expected_seal
            {
                self.fence_wrapper_barrier_delivery();
                super::super::super::erase_json(&mut response.body);
                return Response::error(
                    503,
                    "Wrapper initialization activation unavailable; retrieve the prepared response with the same recovery nonce",
                );
            }
            response
        }
        pub(crate) fn prepare_wrapper_barrier_activation(
            &self,
        ) -> Result<Option<ActivationPlan>, String> {
            let Some(seal) = self.seal.as_ref().filter(|seal| seal.schema == 2) else {
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
            let deadline = operation.deadline;
            Ok(Some(ActivationPlan {
                operation,
                seal: seal.clone(),
                deadline,
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
            if Instant::now() >= completion.deadline
                || self.activate_barrier(&key).is_err()
                || Instant::now() >= completion.deadline
                || load_seal_metadata(&self.data_dir).ok().flatten().as_ref()
                    != Some(&completion.seal)
            {
                self.fence_wrapper_barrier_delivery();
                return Err("Wrapper barrier activation failed closed".into());
            }
            Ok(())
        }
        pub(in crate::service) fn fence_wrapper_barrier_delivery(&mut self) {
            self.fence_openbao_wrapper();
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
pub(crate) use linux::InitializationPlan;

#[cfg(test)]
mod tests {
    use super::*;

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
}
