//! Persisted lease ownership, not a credential registry. Historical service
//! owners remain JSON strings; only verified batch claims create new projections.
use super::batch::{
    BatchAuthorityId, BatchError, BatchKeyId, VerifiedBatchClaims, valid_digest,
    validate_projection,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use zeroize::Zeroize;

/// Existing backends have distinct accepted string formats. Preserve that
/// distinction on old records instead of tightening OpenLDAP or SSH/PKI stores
/// while introducing the batch object format.
#[derive(Clone, Copy)]
pub(crate) enum ServiceOwnerProfile {
    /// SSH/PKI historically accepted 43 base64url alphabet characters, including
    /// a final character whose unused bits are not canonical base64.
    DigestAlphabet,
    /// Database leases already require the canonical 32-byte decoded digest.
    CanonicalDigest,
    /// OpenLDAP historically accepted nonempty ASCII graphic text <=128 bytes.
    Graphic,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum LeaseOwner {
    ServiceToken(ServiceOwner),
    BatchClaims(BatchLeaseClaims),
}

/// No public field or constructor: new service owners must validate a digest;
/// historical strings enter only through the bounded persisted-state decoder.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ServiceOwner(String);
impl Drop for ServiceOwner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "BatchOwnerWire")]
pub(crate) struct BatchLeaseClaims {
    kind: BatchOwnerTag,
    authority_id: BatchAuthorityId,
    key_id: BatchKeyId,
    token_digest: String,
    namespace: String,
    issued_at: u64,
    expires_at: u64,
    parent: Option<String>,
    entity_id: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
enum BatchOwnerTag {
    #[serde(rename = "batch_claims_v1")]
    V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchOwnerWire {
    kind: BatchOwnerTag,
    authority_id: BatchAuthorityId,
    key_id: BatchKeyId,
    token_digest: String,
    namespace: String,
    issued_at: u64,
    expires_at: u64,
    parent: Option<String>,
    entity_id: Option<String>,
}

impl TryFrom<BatchOwnerWire> for BatchLeaseClaims {
    type Error = BatchError;
    fn try_from(value: BatchOwnerWire) -> Result<Self, Self::Error> {
        let claims = Self {
            kind: value.kind,
            authority_id: value.authority_id,
            key_id: value.key_id,
            token_digest: value.token_digest,
            namespace: value.namespace,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            parent: value.parent,
            entity_id: value.entity_id,
        };
        claims.validate()?;
        Ok(claims)
    }
}

impl Drop for BatchLeaseClaims {
    fn drop(&mut self) {
        self.token_digest.zeroize();
        self.namespace.zeroize();
        self.parent.zeroize();
        self.entity_id.zeroize();
    }
}

impl BatchLeaseClaims {
    fn from_verified(claims: &VerifiedBatchClaims) -> Self {
        Self {
            kind: BatchOwnerTag::V1,
            authority_id: claims.authority_id(),
            key_id: claims.key_id(),
            token_digest: claims.token_digest().to_owned(),
            namespace: claims.namespace().to_owned(),
            issued_at: claims.issued_at(),
            expires_at: claims.expires_at(),
            parent: claims.parent().map(str::to_owned),
            entity_id: claims.entity_id().map(str::to_owned),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), BatchError> {
        if !self.authority_id.is_valid()
            || !self.key_id.is_valid()
            || !valid_digest(&self.token_digest)
        {
            return Err(BatchError::InvalidClaims);
        }
        validate_projection(
            &self.namespace,
            self.issued_at,
            self.expires_at,
            self.parent.as_deref(),
            self.entity_id.as_deref(),
        )
    }
    pub(crate) fn authority_id(&self) -> BatchAuthorityId {
        self.authority_id
    }
    pub(crate) fn key_id(&self) -> BatchKeyId {
        self.key_id
    }
    pub(crate) fn token_digest(&self) -> &str {
        &self.token_digest
    }
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }
    pub(crate) fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub(crate) fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub(crate) fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
    pub(crate) fn entity_id(&self) -> Option<&str> {
        self.entity_id.as_deref()
    }
}

impl LeaseOwner {
    pub(crate) fn service(digest: &str) -> Result<Self, BatchError> {
        if !valid_digest(digest) {
            return Err(BatchError::InvalidClaims);
        }
        Ok(Self::ServiceToken(ServiceOwner(digest.to_owned())))
    }
    pub(crate) fn from_batch(claims: &VerifiedBatchClaims) -> Self {
        Self::BatchClaims(BatchLeaseClaims::from_verified(claims))
    }
    pub(crate) fn service_digest(&self) -> Option<&str> {
        match self {
            Self::ServiceToken(owner) => Some(&owner.0),
            Self::BatchClaims(_) => None,
        }
    }
    pub(crate) fn batch_claims(&self) -> Option<&BatchLeaseClaims> {
        match self {
            Self::ServiceToken(_) => None,
            Self::BatchClaims(claims) => Some(claims),
        }
    }
    /// Stable typed ownership; an effective parent expiry computed during a
    /// request is deliberately absent from this comparison and stored shape.
    pub(crate) fn same_credential(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ServiceToken(left), Self::ServiceToken(right)) => left.0 == right.0,
            (Self::BatchClaims(left), Self::BatchClaims(right)) => {
                left.token_digest() == right.token_digest()
            }
            _ => false,
        }
    }
    pub(crate) fn validate_scope(
        &self,
        namespace: &str,
        profile: ServiceOwnerProfile,
    ) -> Result<(), BatchError> {
        match self {
            Self::ServiceToken(owner) => {
                let valid = match profile {
                    ServiceOwnerProfile::DigestAlphabet => {
                        owner.0.len() == 43
                            && owner
                                .0
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                    }
                    ServiceOwnerProfile::CanonicalDigest => valid_digest(&owner.0),
                    ServiceOwnerProfile::Graphic => graphic(&owner.0),
                };
                if !valid {
                    return Err(BatchError::InvalidClaims);
                }
            }
            Self::BatchClaims(claims) => {
                claims.validate()?;
                if claims.namespace != namespace {
                    return Err(BatchError::WrongNamespace);
                }
            }
        }
        Ok(())
    }
}

fn graphic(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

impl Serialize for LeaseOwner {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ServiceToken(owner) => serializer.serialize_str(&owner.0),
            Self::BatchClaims(claims) => claims.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for LeaseOwner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OwnerVisitor;
        impl<'de> de::Visitor<'de> for OwnerVisitor {
            type Value = LeaseOwner;
            fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.write_str("a historical service owner string or tagged batch lease owner")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if !graphic(value) {
                    return Err(E::custom("invalid service lease owner"));
                }
                Ok(LeaseOwner::ServiceToken(ServiceOwner(value.to_owned())))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                // No untagged fallback and no buffering through serde_json::Value.
                BatchLeaseClaims::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(LeaseOwner::BatchClaims)
            }
        }
        deserializer.deserialize_any(OwnerVisitor)
    }
}

#[cfg(test)]
#[path = "auth_lease_owner_tests.rs"]
mod tests;
