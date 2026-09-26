//! Canonical V5 publication identity shared by local storage and HBSM5. This
//! manifest is the authority; object staging alone never publishes state.
use crate::state_records::{AddressKey, Kv1Root, ObjectKind, ObjectRef};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const STORAGE_FORMAT: &str = "heptabao-state-records-v5";
pub(crate) const MAX_ROOT_BYTES: usize = 64 * 1024;
pub(crate) const OWNER_CHUNK_BYTES: usize = 256 * 1024;
pub(crate) const OWNER_NAMES: [&str; 5] =
    ["namespaces", "auth", "engines", "database", "raft_admin"];
const MAX_OWNER_BYTES: u64 = crate::MAX_APPLICATION_STATE_BYTES as u64;
const MAX_OWNER_CHUNKS: usize = crate::MAX_APPLICATION_STATE_BYTES.div_ceil(OWNER_CHUNK_BYTES);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "digest",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum StateIdentity {
    Legacy([u8; 32]),
    RecordsV5([u8; 32]),
}

impl StateIdentity {
    pub(crate) fn digest(&self) -> [u8; 32] {
        match self {
            Self::Legacy(digest) | Self::RecordsV5(digest) => *digest,
        }
    }
}

/// Separate owner boundaries remain intact. KV1 record payloads are excluded
/// from the engines owner and authenticated through the independent tree root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpaqueOwnerRef {
    pub(crate) name: String,
    pub(crate) total_bytes: u64,
    pub(crate) chunks: Vec<ObjectRef>,
    pub(crate) digest: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct PersistedAddressKey([u8; 32]);
impl Drop for PersistedAddressKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordStateRoot {
    storage_format: String,
    pub(crate) state_schema: u32,
    pub(crate) cluster_id: String,
    pub(crate) replay_epoch: u64,
    pub(crate) owners: [OpaqueOwnerRef; 5],
    pub(crate) kv1: Kv1Root,
    object_address_key: PersistedAddressKey,
}

impl std::fmt::Debug for RecordStateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordStateRoot")
            .field("state_schema", &self.state_schema)
            .field("replay_epoch", &self.replay_epoch)
            .field("owners", &self.owners)
            .field("object_address_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootError {
    Invalid,
    TooLarge,
    Serialization,
    Authentication,
}

impl RecordStateRoot {
    pub(crate) fn new(
        state_schema: u32,
        cluster_id: String,
        replay_epoch: u64,
        owners: [OpaqueOwnerRef; 5],
        kv1: Kv1Root,
        address_key: [u8; 32],
    ) -> Result<Self, RootError> {
        let root = Self {
            storage_format: STORAGE_FORMAT.into(),
            state_schema,
            cluster_id,
            replay_epoch,
            owners,
            kv1,
            object_address_key: PersistedAddressKey(address_key),
        };
        root.validate()?;
        Ok(root)
    }

    pub(crate) fn address_key(&self) -> Arc<AddressKey> {
        AddressKey::from_bytes(self.object_address_key.0)
    }

    pub(crate) fn validate(&self) -> Result<(), RootError> {
        if self.storage_format != STORAGE_FORMAT
            || self.state_schema < 36
            || self.object_address_key.0 == [0; 32]
            || self.cluster_id.is_empty()
            || self.cluster_id.len() > 256
            || self.cluster_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(RootError::Invalid);
        }
        let mut owner_total = 0_u64;
        for (owner, expected) in self.owners.iter().zip(OWNER_NAMES) {
            if owner.name != expected
                || owner.total_bytes == 0
                || owner.total_bytes > MAX_OWNER_BYTES
                || owner.chunks.is_empty()
                || owner.chunks.len() > MAX_OWNER_CHUNKS
            {
                return Err(RootError::Invalid);
            }
            let mut bytes = 0_u64;
            for chunk in &owner.chunks {
                if chunk.kind != ObjectKind::OwnerChunk
                    || chunk.record_count != 0
                    || chunk.payload_bytes == 0
                    || chunk.payload_bytes > OWNER_CHUNK_BYTES as u64
                    || chunk.encoded_bytes == 0
                    || chunk.encoded_bytes as usize > 1024 * 1024
                {
                    return Err(RootError::Invalid);
                }
                bytes = bytes
                    .checked_add(chunk.payload_bytes)
                    .ok_or(RootError::TooLarge)?;
            }
            if bytes != owner.total_bytes {
                return Err(RootError::Invalid);
            }
            owner_total = owner_total
                .checked_add(owner.total_bytes)
                .ok_or(RootError::TooLarge)?;
        }
        if owner_total > MAX_OWNER_BYTES {
            return Err(RootError::TooLarge);
        }
        match &self.kv1.reference {
            None if self.kv1.height == 0 => {}
            Some(reference)
                if (1..=16).contains(&self.kv1.height)
                    && reference.encoded_bytes as usize <= crate::state_records::PAGE_BYTES
                    && reference.encoded_bytes > 0
                    && reference.record_count > 0
                    && reference.payload_bytes > 0
                    && ((self.kv1.height == 1
                        && matches!(
                            reference.kind,
                            ObjectKind::Leaf | ObjectKind::PackedLeaf
                        ))
                        || (self.kv1.height > 1 && reference.kind == ObjectKind::Branch)) => {}
            _ => return Err(RootError::Invalid),
        }
        // Core opening separately validates the complete immutable closure.
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RootError> {
        self.validate()?;
        crate::secret_serde::to_vec(self, MAX_ROOT_BYTES).map_err(|error| match error {
            crate::secret_serde::Error::TooLarge => RootError::TooLarge,
            crate::secret_serde::Error::Serialization => RootError::Serialization,
        })
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, RootError> {
        if bytes.len() > MAX_ROOT_BYTES {
            return Err(RootError::TooLarge);
        }
        let root: Self = serde_json::from_slice(bytes).map_err(|_| RootError::Invalid)?;
        root.validate()?;
        if root.encode()?.as_slice() != bytes {
            return Err(RootError::Invalid);
        }
        Ok(root)
    }

    pub(crate) fn identity(&self) -> Result<StateIdentity, RootError> {
        let bytes = self.encode()?;
        let digest = self
            .address_key()
            .digest(b"state-root-v5", &bytes)
            .map_err(|_| RootError::Authentication)?;
        Ok(StateIdentity::RecordsV5(digest))
    }

    pub(crate) fn references(&self) -> impl Iterator<Item = &ObjectRef> {
        self.owners
            .iter()
            .flat_map(|owner| owner.chunks.iter())
            .chain(self.kv1.reference.iter())
    }

    pub(crate) fn owner_digest(&self, name: &str, bytes: &[u8]) -> Result<[u8; 32], RootError> {
        digest_owner(&self.address_key(), name, bytes)
    }
}

pub(crate) fn digest_owner(
    key: &AddressKey,
    name: &str,
    bytes: &[u8],
) -> Result<[u8; 32], RootError> {
    if !OWNER_NAMES.contains(&name) || bytes.len() > crate::MAX_APPLICATION_STATE_BYTES {
        return Err(RootError::Invalid);
    }
    let domain = format!("state-owner-v5/{name}");
    key.digest(domain.as_bytes(), bytes)
        .map_err(|_| RootError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_records::{ObjectId, StagedObject};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn fixture(kind: ObjectKind, height: u8) -> TestResult<RecordStateRoot> {
        let key = AddressKey::from_bytes([7; 32]);
        let chunk = StagedObject::owner_chunk(&key, b"{}")?;
        let owners = OWNER_NAMES
            .into_iter()
            .map(|name| {
                Ok(OpaqueOwnerRef {
                    name: name.into(),
                    total_bytes: 2,
                    chunks: vec![chunk.reference().clone()],
                    digest: digest_owner(&key, name, b"{}").map_err(|_| "owner digest")?,
                })
            })
            .collect::<TestResult<Vec<_>>>()?
            .try_into()
            .map_err(|_| "owners")?;
        RecordStateRoot::new(
            37,
            "packed-root-test".into(),
            0,
            owners,
            Kv1Root {
                reference: Some(ObjectRef {
                    id: ObjectId::from_bytes([8; 32]),
                    kind,
                    encoded_bytes: 100,
                    record_count: 1,
                    payload_bytes: 4,
                }),
                height,
            },
            [7; 32],
        )
        .map_err(|_| "invalid fixture root".into())
    }

    #[test]
    fn direct_packed_leaf_root_roundtrips_without_changing_old_leaf_or_branch_shapes() -> TestResult
    {
        for (kind, height) in [
            (ObjectKind::Leaf, 1),
            (ObjectKind::PackedLeaf, 1),
            (ObjectKind::Branch, 2),
        ] {
            let root = fixture(kind, height)?;
            let bytes = root.encode().map_err(|_| "encode")?;
            let decoded = RecordStateRoot::decode(&bytes).map_err(|_| "decode")?;
            assert_eq!(decoded.kv1, root.kv1);
            assert_eq!(
                decoded.identity().map_err(|_| "identity")?,
                root.identity().map_err(|_| "identity")?
            );
        }
        Ok(())
    }

    #[test]
    fn packed_root_rejects_wrong_levels_owner_roles_and_unknown_kind() -> TestResult {
        for (kind, height) in [
            (ObjectKind::PackedLeaf, 2),
            (ObjectKind::Leaf, 2),
            (ObjectKind::Branch, 1),
            (ObjectKind::Block, 1),
            (ObjectKind::Value, 1),
            (ObjectKind::OwnerChunk, 1),
            (ObjectKind::PackedLeaf, 0),
        ] {
            let mut root = fixture(ObjectKind::PackedLeaf, 1)?;
            root.kv1.height = height;
            root.kv1.reference.as_mut().ok_or("reference")?.kind = kind;
            assert!(root.validate().is_err());
            assert!(root.encode().is_err());
        }
        let mut root = fixture(ObjectKind::PackedLeaf, 1)?;
        root.owners[0].chunks[0].kind = ObjectKind::PackedLeaf;
        assert!(root.validate().is_err());
        let root = fixture(ObjectKind::PackedLeaf, 1)?;
        let bytes = root.encode().map_err(|_| "encode")?;
        let text = std::str::from_utf8(&bytes)?.replace("PackedLeaf", "UnknownPage");
        assert!(RecordStateRoot::decode(text.as_bytes()).is_err());
        Ok(())
    }
}
