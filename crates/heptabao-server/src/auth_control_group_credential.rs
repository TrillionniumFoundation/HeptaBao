//! Internal issuer-sealed credentials, never a bearer or persisted Principal.
use super::*;

const CUSTODY_DOMAIN: &[u8] = b"heptabao.control-group.credential-custody.v1\0";
const MAX_CIPHERTEXT: usize = MAX_BATCH_TOKEN_BYTES + TAG_BYTES;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CredentialKind {
    BatchResumeV1,
    ServiceEchoV1,
}
impl CredentialKind {
    pub(crate) fn is_batch(self) -> bool {
        self == Self::BatchResumeV1
    }
    fn accepts(self, raw: &str) -> bool {
        match self {
            Self::BatchResumeV1 => raw.starts_with("hvb.") && raw.len() <= MAX_BATCH_TOKEN_BYTES,
            Self::ServiceEchoV1 => raw.starts_with("hvs.") && raw.len() <= 256,
        }
    }
    fn marker(self) -> u8 {
        match self {
            Self::BatchResumeV1 => 1,
            Self::ServiceEchoV1 => 2,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "CapsuleWire")]
pub(crate) struct CredentialCapsule {
    kind: CredentialKind,
    authority_id: BatchAuthorityId,
    key_id: BatchKeyId,
    nonce: [u8; NONCE_BYTES],
    binding: [u8; 32],
    ciphertext: Vec<u8>,
}
impl Drop for CredentialCapsule {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapsuleWire {
    kind: CredentialKind,
    authority_id: BatchAuthorityId,
    key_id: BatchKeyId,
    nonce: [u8; NONCE_BYTES],
    binding: [u8; 32],
    #[serde(deserialize_with = "bounded_ciphertext")]
    ciphertext: Vec<u8>,
}
fn bounded_ciphertext<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct BoundedCiphertext;
    impl<'de> de::Visitor<'de> for BoundedCiphertext {
        type Value = Vec<u8>;
        fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str("a bounded control-group issuer ciphertext")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut result = Zeroizing::new(Vec::new());
            while let Some(byte) = seq.next_element::<u8>()? {
                if result.len() == MAX_CIPHERTEXT {
                    return Err(de::Error::custom(
                        "control-group issuer ciphertext exceeds bound",
                    ));
                }
                result.push(byte);
            }
            Ok(std::mem::take(&mut *result))
        }
    }
    decoder.deserialize_seq(BoundedCiphertext)
}
impl TryFrom<CapsuleWire> for CredentialCapsule {
    type Error = BatchError;
    fn try_from(wire: CapsuleWire) -> Result<Self, Self::Error> {
        let capsule = Self {
            kind: wire.kind,
            authority_id: wire.authority_id,
            key_id: wire.key_id,
            nonce: wire.nonce,
            binding: wire.binding,
            ciphertext: wire.ciphertext,
        };
        capsule.validate()?;
        Ok(capsule)
    }
}
impl CredentialCapsule {
    pub(crate) fn kind(&self) -> CredentialKind {
        self.kind
    }
    pub(crate) fn validate(&self) -> Result<(), BatchError> {
        if !self.authority_id.is_valid()
            || !self.key_id.is_valid()
            || self.ciphertext.len() <= TAG_BYTES
            || self.ciphertext.len() > MAX_CIPHERTEXT
        {
            return Err(BatchError::InvalidClaims);
        }
        Ok(())
    }
}
fn custody_aad(
    authority: BatchAuthorityId,
    key: BatchKeyId,
    kind: CredentialKind,
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CUSTODY_DOMAIN.len() + AUTHORITY_BYTES + KEY_ID_BYTES + 33);
    aad.extend_from_slice(CUSTODY_DOMAIN);
    aad.extend_from_slice(&authority.0);
    aad.extend_from_slice(&key.0);
    aad.push(kind.marker());
    aad.extend_from_slice(binding);
    aad
}
impl BatchKeyAuthority {
    pub(crate) fn capture_control_group_credential(
        &mut self,
        raw: &str,
        kind: CredentialKind,
        binding: [u8; 32],
        now: u64,
        expires_at: u64,
    ) -> Result<CredentialCapsule, BatchError> {
        self.validate()?;
        if !kind.accepts(raw) || expires_at <= now || expires_at - now > MAX_BATCH_TTL {
            return Err(BatchError::InvalidClaims);
        }
        let key = self
            .keys
            .iter()
            .find(|key| key.id == self.active_key)
            .ok_or(BatchError::InvalidAuthority)?;
        if now < key.last_issued_at {
            return Err(BatchError::ClockRollback);
        }
        let mut nonce = [0; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| BatchError::Randomness)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.secret.0.as_slice())
            .map_err(|_| BatchError::InvalidAuthority)?;
        let mut ciphertext = Zeroizing::new(raw.as_bytes().to_vec());
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &custody_aad(self.authority_id, key.id, kind, &binding),
                &mut ciphertext,
            )
            .map_err(|_| BatchError::InvalidToken)?;
        ciphertext.extend_from_slice(&tag);
        let capsule = CredentialCapsule {
            kind,
            authority_id: self.authority_id,
            key_id: key.id,
            nonce,
            binding,
            ciphertext: std::mem::take(&mut *ciphertext),
        };
        capsule.validate()?;
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.id == self.active_key)
            .ok_or(BatchError::InvalidAuthority)?;
        key.last_issued_at = now;
        key.max_issued_expiry = key.max_issued_expiry.max(expires_at);
        Ok(capsule)
    }
    pub(crate) fn open_control_group_credential(
        &self,
        capsule: &CredentialCapsule,
        binding: [u8; 32],
    ) -> Result<Zeroizing<String>, BatchError> {
        self.validate()?;
        capsule.validate()?;
        if binding != capsule.binding {
            return Err(BatchError::InvalidClaims);
        }
        let key = self.find_key(capsule.authority_id, capsule.key_id)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.secret.0.as_slice())
            .map_err(|_| BatchError::InvalidAuthority)?;
        let mut plaintext = Zeroizing::new(capsule.ciphertext.clone());
        let split = plaintext.len() - TAG_BYTES;
        let (body, tag) = plaintext.split_at_mut(split);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&capsule.nonce),
                &custody_aad(capsule.authority_id, capsule.key_id, capsule.kind, &binding),
                body,
                chacha20poly1305::Tag::from_slice(tag),
            )
            .map_err(|_| BatchError::InvalidToken)?;
        let raw = Zeroizing::new(
            std::str::from_utf8(body)
                .map_err(|_| BatchError::InvalidToken)?
                .to_owned(),
        );
        if !capsule.kind.accepts(&raw) {
            return Err(BatchError::InvalidToken);
        }
        Ok(raw)
    }
    // Structural sealed ownership admission deliberately does not revive an
    // expired request credential or construct a Principal.
    pub(crate) fn validate_control_group_batch_raw(
        &self,
        raw: &str,
        namespace: &str,
        entity_id: &str,
    ) -> Result<(), BatchError> {
        let claims = self.open_authenticated_payload(raw)?;
        if claims.namespace() != namespace || claims.entity_id() != Some(entity_id) {
            return Err(BatchError::InvalidClaims);
        }
        Ok(())
    }
}
