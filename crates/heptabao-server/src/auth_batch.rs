//! Stateless batch cryptography. This module does not admit requests or publish
//! credentials: the caller must commit its candidate Auth owner before exposing
//! a sealed bearer, and must recheck parent, Identity, CIDR and ACL authority.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Write,
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const MAX_BATCH_CLAIMS_BYTES: usize = 8 * 1024;
pub(crate) const MAX_BATCH_TOKEN_BYTES: usize = 16 * 1024;
pub(crate) const MAX_BATCH_KEYS: usize = 8;
const MAX_BATCH_TTL: u64 = super::MAX_TTL;
// A native JWT display name contains a bounded auth mount, '-' and subject.
// Keep the full identity; the total authenticated claims still fit the 8 KiB cap.
const MAX_BATCH_DISPLAY_NAME_BYTES: usize = 256 + 1 + 1024;
const PREFIX: &str = "hvb.";
const MAGIC: &[u8; 4] = b"HBB1";
const DOMAIN: &[u8] = b"heptabao.batch.claims.v1\0";
const AUTHORITY_BYTES: usize = 16;
const KEY_ID_BYTES: usize = 32;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 4 + AUTHORITY_BYTES + KEY_ID_BYTES + NONCE_BYTES;
const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_BATCH_CLAIMS_BYTES + TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchError {
    InvalidClaims,
    InvalidAuthority,
    InvalidToken,
    WrongNamespace,
    ExpiredOrFuture,
    ClockRollback,
    Capacity,
    Randomness,
}

impl fmt::Display for BatchError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::InvalidClaims => "invalid batch claims",
            Self::InvalidAuthority => "invalid batch key authority",
            Self::InvalidToken => "invalid batch token",
            Self::WrongNamespace => "batch namespace mismatch",
            Self::ExpiredOrFuture => "batch token expired or not yet valid",
            Self::ClockRollback => "batch issuance clock moved backwards",
            Self::Capacity => "batch encoding exceeds bounded capacity",
            Self::Randomness => "batch secure randomness unavailable",
        })
    }
}
impl std::error::Error for BatchError {}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct BatchAuthorityId([u8; AUTHORITY_BYTES]);

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct BatchKeyId([u8; KEY_ID_BYTES]);

impl BatchAuthorityId {
    pub(crate) fn is_valid(self) -> bool {
        self.0 != [0; AUTHORITY_BYTES]
    }
}
impl BatchKeyId {
    pub(crate) fn is_valid(self) -> bool {
        self.0 != [0; KEY_ID_BYTES]
    }
}

// No Debug and no non-zeroizing key copy in the base64 serializer/decoder.
#[derive(Clone)]
struct SecretKey(Zeroizing<[u8; 32]>);
impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0.as_slice()));
        serializer.serialize_str(&encoded)
    }
}
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl de::Visitor<'_> for KeyVisitor {
            type Value = SecretKey;
            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a canonical 32-byte batch key")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let mut key = Zeroizing::new([0; 32]);
                if value.len() != 43
                    || URL_SAFE_NO_PAD.decode_slice(value, key.as_mut_slice()).ok() != Some(32)
                {
                    return Err(E::custom("invalid batch key"));
                }
                Ok(SecretKey(key))
            }
        }
        deserializer.deserialize_str(KeyVisitor)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    id: BatchKeyId,
    secret: SecretKey,
    created_at: u64,
    last_issued_at: u64,
    /// Observation only, not an authentication or safe key-retirement bound.
    /// Restoring an older owner can roll this watermark back while the same key
    /// still authenticates an unexpired token issued after that snapshot.
    max_issued_expiry: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "StoredAuthority")]
pub(crate) struct BatchKeyAuthority {
    version: u8,
    authority_id: BatchAuthorityId,
    active_key: BatchKeyId,
    keys: Vec<KeyRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredAuthority {
    version: u8,
    authority_id: BatchAuthorityId,
    active_key: BatchKeyId,
    #[serde(deserialize_with = "bounded_keys")]
    keys: Vec<KeyRecord>,
}

fn bounded_keys<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<KeyRecord>, D::Error> {
    struct KeysVisitor;
    impl<'de> de::Visitor<'de> for KeysVisitor {
        type Value = Vec<KeyRecord>;
        fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
            out.write_str("a bounded batch key list")
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut keys = Vec::with_capacity(MAX_BATCH_KEYS);
            while let Some(key) = seq.next_element()? {
                if keys.len() == MAX_BATCH_KEYS {
                    return Err(de::Error::custom("too many batch keys"));
                }
                keys.push(key);
            }
            Ok(keys)
        }
    }
    deserializer.deserialize_seq(KeysVisitor)
}

impl TryFrom<StoredAuthority> for BatchKeyAuthority {
    type Error = BatchError;
    fn try_from(value: StoredAuthority) -> Result<Self, Self::Error> {
        let authority = Self {
            version: value.version,
            authority_id: value.authority_id,
            active_key: value.active_key,
            keys: value.keys,
        };
        authority.validate()?;
        Ok(authority)
    }
}

/// Untrusted issuance input. Resolve the canonical Identity entity before
/// constructing this value. Validation does not confer permission to issue it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BatchClaims {
    pub(crate) namespace: String,
    pub(crate) policies: BTreeSet<String>,
    pub(crate) metadata: BTreeMap<String, String>,
    pub(crate) display_name: String,
    pub(crate) path: String,
    pub(crate) bound_cidrs: Vec<String>,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) parent: Option<String>,
    pub(crate) entity_id: Option<String>,
}

impl Drop for BatchClaims {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.display_name.zeroize();
        self.path.zeroize();
        for mut policy in std::mem::take(&mut self.policies) {
            policy.zeroize();
        }
        for (mut key, mut value) in std::mem::take(&mut self.metadata) {
            key.zeroize();
            value.zeroize();
        }
        self.bound_cidrs.zeroize();
        self.parent.zeroize();
        self.entity_id.zeroize();
    }
}

/// Only `open` constructs this type. It is not Deserialize, Clone or Debug and
/// does not embed a service Token. Revalidation needs current key authority plus
/// the caller's live parent/Identity/ACL checks, not a per-batch backing record.
pub(crate) struct VerifiedBatchClaims {
    claims: BatchClaims,
    authority_id: BatchAuthorityId,
    key_id: BatchKeyId,
    token_digest: Zeroizing<String>,
}

impl VerifiedBatchClaims {
    pub(crate) fn namespace(&self) -> &str {
        &self.claims.namespace
    }
    pub(crate) fn policies(&self) -> &BTreeSet<String> {
        &self.claims.policies
    }
    pub(crate) fn metadata(&self) -> &BTreeMap<String, String> {
        &self.claims.metadata
    }
    pub(crate) fn display_name(&self) -> &str {
        &self.claims.display_name
    }
    pub(crate) fn path(&self) -> &str {
        &self.claims.path
    }
    pub(crate) fn bound_cidrs(&self) -> &[String] {
        &self.claims.bound_cidrs
    }
    pub(crate) fn issued_at(&self) -> u64 {
        self.claims.issued_at
    }
    pub(crate) fn expires_at(&self) -> u64 {
        self.claims.expires_at
    }
    pub(crate) fn parent(&self) -> Option<&str> {
        self.claims.parent.as_deref()
    }
    pub(crate) fn entity_id(&self) -> Option<&str> {
        self.claims.entity_id.as_deref()
    }
    pub(crate) fn token_digest(&self) -> &str {
        &self.token_digest
    }
    pub(crate) fn authority_id(&self) -> BatchAuthorityId {
        self.authority_id
    }
    pub(crate) fn key_id(&self) -> BatchKeyId {
        self.key_id
    }
}

/// Contains a bearer. The enclosing transaction must publish the authority
/// candidate before exposing this value; cryptographic sealing is not a commit.
pub(crate) struct BatchToken(Zeroizing<String>);
impl BatchToken {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn valid_digest(value: &str) -> bool {
    let mut decoded = [0; 32];
    value.len() == 43 && URL_SAFE_NO_PAD.decode_slice(value, &mut decoded).ok() == Some(32)
}

pub(crate) fn validate_projection(
    namespace: &str,
    issued_at: u64,
    expires_at: u64,
    parent: Option<&str>,
    entity_id: Option<&str>,
) -> Result<(), BatchError> {
    super::validate_namespace(namespace).map_err(|_| BatchError::InvalidClaims)?;
    if expires_at <= issued_at
        || expires_at - issued_at > MAX_BATCH_TTL
        || parent.is_some_and(|id| !valid_digest(id))
        || entity_id.is_some_and(|id| !super::valid_name(id))
    {
        return Err(BatchError::InvalidClaims);
    }
    Ok(())
}

impl BatchClaims {
    fn validate(&self) -> Result<(), BatchError> {
        validate_projection(
            &self.namespace,
            self.issued_at,
            self.expires_at,
            self.parent.as_deref(),
            self.entity_id.as_deref(),
        )?;
        if self.display_name.is_empty()
            || self.display_name.len() > MAX_BATCH_DISPLAY_NAME_BYTES
            || self.display_name.chars().any(char::is_control)
            || self.path.is_empty()
            || self.path.len() > 2048
            || self.path.chars().any(char::is_control)
            || self.policies.len() > 128
            || self
                .policies
                .iter()
                .any(|p| !super::valid_name(p) || p == "root")
            || self.metadata.len() > 64
            || self.metadata.iter().any(|(key, value)| {
                key.is_empty()
                    || key.len() > 128
                    || value.len() > 1024
                    || key.chars().any(char::is_control)
                    || value.chars().any(char::is_control)
            })
        {
            return Err(BatchError::InvalidClaims);
        }
        super::token_cidrs::validate(&self.bound_cidrs).map_err(|_| BatchError::InvalidClaims)
    }
}

fn check_time(issued_at: u64, expires_at: u64, now: u64) -> Result<(), BatchError> {
    if now < issued_at || now >= expires_at {
        Err(BatchError::ExpiredOrFuture)
    } else {
        Ok(())
    }
}

// One preallocated zeroizing allocation; serde never grows a plaintext Vec.
struct ClaimsWriter(Zeroizing<Vec<u8>>);
impl Write for ClaimsWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_BATCH_CLAIMS_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("batch claims capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode_claims(claims: &BatchClaims) -> Result<Zeroizing<Vec<u8>>, BatchError> {
    let mut writer = ClaimsWriter(Zeroizing::new(Vec::with_capacity(
        MAX_BATCH_CLAIMS_BYTES + TAG_BYTES,
    )));
    serde_json::to_writer(&mut writer, claims).map_err(|_| BatchError::Capacity)?;
    Ok(writer.0)
}
fn key_id(secret: &SecretKey) -> BatchKeyId {
    let mut id = [0; 32];
    id.copy_from_slice(digest::digest(&digest::SHA256, secret.0.as_slice()).as_ref());
    BatchKeyId(id)
}
fn associated_data(authority: BatchAuthorityId, key: BatchKeyId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + MAGIC.len() + AUTHORITY_BYTES + KEY_ID_BYTES);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&authority.0);
    aad.extend_from_slice(&key.0);
    aad
}

impl BatchKeyAuthority {
    #[cfg(test)]
    pub(super) fn is_unused_for_legacy_fixture(&self) -> bool {
        self.keys.len() == 1
            && self.keys.iter().all(|key| {
                key.created_at == key.last_issued_at && key.created_at == key.max_issued_expiry
            })
    }
    pub(crate) fn new(now: u64) -> Result<Self, BatchError> {
        let random = SystemRandom::new();
        let mut authority = [0; AUTHORITY_BYTES];
        let mut secret = Zeroizing::new([0; 32]);
        random
            .fill(&mut authority)
            .map_err(|_| BatchError::Randomness)?;
        random
            .fill(secret.as_mut_slice())
            .map_err(|_| BatchError::Randomness)?;
        let secret = SecretKey(secret);
        let key = key_id(&secret);
        let result = Self {
            version: 1,
            authority_id: BatchAuthorityId(authority),
            active_key: key,
            keys: vec![KeyRecord {
                id: key,
                secret,
                created_at: now,
                last_issued_at: now,
                max_issued_expiry: now,
            }],
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn validate(&self) -> Result<(), BatchError> {
        let mut ids = BTreeSet::new();
        if self.version != 1
            || !self.authority_id.is_valid()
            || self.keys.is_empty()
            || self.keys.len() > MAX_BATCH_KEYS
        {
            return Err(BatchError::InvalidAuthority);
        }
        for key in &self.keys {
            if !key.id.is_valid()
                || key.id != key_id(&key.secret)
                || !ids.insert(key.id)
                || key.last_issued_at < key.created_at
                || key.max_issued_expiry < key.last_issued_at
                || key.max_issued_expiry > key.last_issued_at.saturating_add(MAX_BATCH_TTL)
            {
                return Err(BatchError::InvalidAuthority);
            }
        }
        if !ids.contains(&self.active_key) {
            return Err(BatchError::InvalidAuthority);
        }
        Ok(())
    }

    /// No rotation or pruning API is exposed. A restored older expiry watermark
    /// is not a safe retirement bound; that requires a separate recovery policy.
    pub(crate) fn seal(&mut self, claims: BatchClaims, now: u64) -> Result<BatchToken, BatchError> {
        self.validate()?;
        claims.validate()?;
        if claims.issued_at != now {
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
        let mut plaintext = encode_claims(&claims)?;
        let mut nonce = [0; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| BatchError::Randomness)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.secret.0.as_slice())
            .map_err(|_| BatchError::InvalidAuthority)?;
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &associated_data(self.authority_id, key.id),
                plaintext.as_mut_slice(),
            )
            .map_err(|_| BatchError::InvalidToken)?;
        let mut envelope = Zeroizing::new(Vec::with_capacity(MAX_ENVELOPE_BYTES));
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&self.authority_id.0);
        envelope.extend_from_slice(&key.id.0);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&plaintext);
        envelope.extend_from_slice(&tag);
        let mut encoded = Zeroizing::new(String::with_capacity(MAX_BATCH_TOKEN_BYTES));
        encoded.push_str(PREFIX);
        URL_SAFE_NO_PAD.encode_string(envelope.as_slice(), &mut encoded);
        if encoded.len() > MAX_BATCH_TOKEN_BYTES {
            return Err(BatchError::Capacity);
        }
        // All fallible operations precede the candidate's monotonic watermark.
        let key = self
            .keys
            .iter_mut()
            .find(|key| key.id == self.active_key)
            .ok_or(BatchError::InvalidAuthority)?;
        key.last_issued_at = now;
        key.max_issued_expiry = key.max_issued_expiry.max(claims.expires_at);
        Ok(BatchToken(encoded))
    }

    pub(crate) fn open(
        &self,
        raw: &str,
        namespace: &str,
        now: u64,
    ) -> Result<VerifiedBatchClaims, BatchError> {
        let claims = self.open_authenticated(raw, now)?;
        if claims.namespace() != namespace {
            return Err(BatchError::WrongNamespace);
        }
        Ok(claims)
    }

    /// Authenticates the namespace inside the ciphertext. The request dispatcher
    /// must still compare it to its trusted target namespace before authorization.
    pub(crate) fn open_authenticated(
        &self,
        raw: &str,
        now: u64,
    ) -> Result<VerifiedBatchClaims, BatchError> {
        self.validate()?;
        if raw.len() > MAX_BATCH_TOKEN_BYTES {
            return Err(BatchError::Capacity);
        }
        let encoded = raw.strip_prefix(PREFIX).ok_or(BatchError::InvalidToken)?;
        // Decode into a fixed upper bound; malformed/oversize input never asks
        // base64 or serde to allocate based on attacker-declared contents.
        let mut envelope = Zeroizing::new(vec![0; MAX_ENVELOPE_BYTES]);
        let length = URL_SAFE_NO_PAD
            .decode_slice(encoded, envelope.as_mut_slice())
            .map_err(|_| BatchError::InvalidToken)?;
        if length < HEADER_BYTES + TAG_BYTES || &envelope[..4] != MAGIC {
            return Err(BatchError::InvalidToken);
        }
        envelope.truncate(length);
        let mut authority = [0; AUTHORITY_BYTES];
        authority.copy_from_slice(&envelope[4..4 + AUTHORITY_BYTES]);
        let mut id = [0; KEY_ID_BYTES];
        id.copy_from_slice(&envelope[4 + AUTHORITY_BYTES..4 + AUTHORITY_BYTES + KEY_ID_BYTES]);
        let authority = BatchAuthorityId(authority);
        let id = BatchKeyId(id);
        let key = self.find_key(authority, id)?;
        let mut nonce = [0; NONCE_BYTES];
        nonce.copy_from_slice(&envelope[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES]);
        let cipher = XChaCha20Poly1305::new_from_slice(key.secret.0.as_slice())
            .map_err(|_| BatchError::InvalidAuthority)?;
        let body = &mut envelope[HEADER_BYTES..];
        let split = body.len() - TAG_BYTES;
        let (plaintext, tag) = body.split_at_mut(split);
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(&nonce),
                &associated_data(authority, id),
                plaintext,
                chacha20poly1305::Tag::from_slice(tag),
            )
            .map_err(|_| BatchError::InvalidToken)?;
        let claims: BatchClaims =
            serde_json::from_slice(plaintext).map_err(|_| BatchError::InvalidClaims)?;
        claims.validate()?;
        // Canonical form also rejects duplicate map/set entries and alternate
        // spellings, rather than allowing two encodings of the same authority.
        if encode_claims(&claims)?.as_slice() != plaintext {
            return Err(BatchError::InvalidClaims);
        }
        if claims.issued_at < key.created_at {
            return Err(BatchError::InvalidToken);
        }
        check_time(claims.issued_at, claims.expires_at, now)?;
        Ok(VerifiedBatchClaims {
            claims,
            authority_id: authority,
            key_id: id,
            token_digest: Zeroizing::new(super::hash(raw)),
        })
    }

    fn find_key(
        &self,
        authority: BatchAuthorityId,
        id: BatchKeyId,
    ) -> Result<&KeyRecord, BatchError> {
        if authority != self.authority_id {
            return Err(BatchError::InvalidAuthority);
        }
        self.keys
            .iter()
            .find(|key| key.id == id)
            .ok_or(BatchError::InvalidAuthority)
    }

    pub(crate) fn check_verified(
        &self,
        claims: &VerifiedBatchClaims,
        namespace: &str,
        now: u64,
    ) -> Result<(), BatchError> {
        self.validate()?;
        let key = self.find_key(claims.authority_id(), claims.key_id())?;
        if namespace != claims.namespace() {
            return Err(BatchError::WrongNamespace);
        }
        if claims.issued_at() < key.created_at {
            return Err(BatchError::InvalidToken);
        }
        check_time(claims.issued_at(), claims.expires_at(), now)
    }

    pub(crate) fn check_lease(
        &self,
        claims: &super::lease_owner::BatchLeaseClaims,
        namespace: &str,
        now: u64,
    ) -> Result<(), BatchError> {
        self.validate_lease_authority(claims, namespace)?;
        check_time(claims.issued_at(), claims.expires_at(), now)
    }

    /// Loading an expired owner must remain possible so provider maintenance can
    /// revoke it. Persistent admission checks key identity and scope separately
    /// from the current-time liveness check used for issuing or renewing a lease.
    pub(crate) fn validate_lease_authority(
        &self,
        claims: &super::lease_owner::BatchLeaseClaims,
        namespace: &str,
    ) -> Result<(), BatchError> {
        claims.validate()?;
        self.validate()?;
        let key = self.find_key(claims.authority_id(), claims.key_id())?;
        if claims.namespace() != namespace {
            return Err(BatchError::WrongNamespace);
        }
        if claims.issued_at() < key.created_at {
            return Err(BatchError::InvalidToken);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "auth_batch_tests.rs"]
mod tests;
