//! Typed V6 encrypted resources. Syntax/retention is never capability admission.
use crate::state_record_root_v6::OwnerDomain;
use crate::state_records::{ObjectId, ObjectKind, ObjectRef, RecordError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "domain", rename_all = "snake_case", deny_unknown_fields)]
pub enum CipherDomain {
    ProtectedOwner { role: OwnerDomain },
    Kv1,
    RootKv2 { scope: [u8; 32] },
    NamespaceKv2 { owner: [u8; 32], scope: [u8; 32] },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherReference {
    pub domain: CipherDomain,
    pub id: [u8; 32],
    pub kind: u8,
    pub encoded_bytes: u32,
    pub record_count: u64,
    pub payload_bytes: u64,
}
impl CipherReference {
    pub(crate) fn new(domain: CipherDomain, reference: &ObjectRef) -> Self {
        Self { domain, id: *reference.id.bytes(), kind: reference.kind as u8,
            encoded_bytes: reference.encoded_bytes, record_count: reference.record_count,
            payload_bytes: reference.payload_bytes }
    }
    pub(crate) fn plain_reference(&self) -> Result<ObjectRef, RecordError> {
        let kind = match self.kind {
            1 => ObjectKind::Block, 2 => ObjectKind::Value, 3 => ObjectKind::Leaf,
            4 => ObjectKind::Branch, 5 => ObjectKind::OwnerChunk, 6 => ObjectKind::PackedLeaf,
            _ => return Err(RecordError::Invalid),
        };
        if self.encoded_bytes < 25
            || self.encoded_bytes as usize > crate::state_records::BLOCK_BYTES + 25
            || matches!(kind, ObjectKind::Leaf | ObjectKind::Branch | ObjectKind::PackedLeaf)
                && self.encoded_bytes as usize > crate::state_records::PAGE_BYTES
            || self.payload_bytes > crate::state_records::MAX_GRAPH_BYTES as u64
            || self.record_count > 1_048_576 {
            return Err(RecordError::TooLarge);
        }
        Ok(ObjectRef { id: ObjectId::from_bytes(self.id), kind,
            encoded_bytes: self.encoded_bytes, record_count: self.record_count,
            payload_bytes: self.payload_bytes })
    }
    pub fn resource(&self) -> String {
        fn hex(bytes: &[u8]) -> String {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            bytes.iter().flat_map(|byte| [char::from(DIGITS[(byte >> 4) as usize]),
                char::from(DIGITS[(byte & 15) as usize])]).collect()
        }
        let role = match self.domain {
            CipherDomain::ProtectedOwner { role } => format!("owner/{}", role.name()),
            CipherDomain::Kv1 => "kv1".to_owned(),
            CipherDomain::RootKv2 { scope } => format!("root-kv2/{}", hex(&scope)),
            CipherDomain::NamespaceKv2 { owner, scope } =>
                format!("namespace-kv2/{}/{}", hex(&owner), hex(&scope)),
        };
        format!("state-records/v6/{role}/{}", hex(&self.id))
    }
    pub(crate) fn aad(&self, cluster: &str, replay_epoch: u64) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        self.plain_reference()?;
        if cluster.is_empty() || cluster.len() > 128 || cluster.bytes().any(|b| b.is_ascii_control()) {
            return Err(RecordError::Invalid);
        }
        let mut result = Zeroizing::new(b"HeptaBao/v6/encrypted-object\0".to_vec());
        result.extend_from_slice(&(cluster.len() as u64).to_be_bytes());
        result.extend_from_slice(cluster.as_bytes());
        result.extend_from_slice(&replay_epoch.to_be_bytes());
        let encoded = crate::secret_serde::to_vec(self, 4096).map_err(|_| RecordError::Invalid)?;
        result.extend_from_slice(&encoded);
        Ok(result)
    }
}

/// The pin owns encrypted cells only. No decoder view, NamespaceKey or address
/// key can be placed in this type or transported by serializing it.
pub struct CipherObject {
    pub reference: CipherReference,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}
impl CipherObject {
    pub fn ciphertext(&self) -> &[u8] { &self.bytes }
    pub(crate) fn validate(&self) -> Result<(), RecordError> {
        self.reference.plain_reference()?;
        if self.bytes.len() != self.reference.encoded_bytes as usize + 32
            || !self.bytes.starts_with(b"HBA1") {
            return Err(RecordError::Corrupt);
        }
        Ok(())
    }
}
