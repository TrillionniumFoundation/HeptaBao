//! Distinct V6 publication identity and role-bound reader manifest.
//! Construction or successful decoding never grants Service writer authority.
use crate::engines::kv2_native_records::NativeScope;
use crate::state_record_root::{MAX_ROOT_BYTES, OpaqueOwnerRef, RootError, StateIdentity};
use crate::state_records::{AddressKey, Kv1Key, Kv1Root, ObjectKind, ObjectRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const STORAGE_FORMAT: &str = "heptabao-state-records-v6";
pub(crate) const ENGINE_FORMAT: &str = "heptabao-engines-record-metadata-v6";
pub(crate) const MAX_KV2_MOUNTS: usize = 128;
pub(crate) const READER_FORMAT: u32 = 6;
const MAX_KV1_RECORDS: u64 = 1_048_576;
const MAX_KV2_RECORDS: u64 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerDomain {
    Namespaces,
    Auth,
    Engines,
    Database,
    RaftAdmin,
}
impl OwnerDomain {
    pub(crate) const ALL: [Self; 5] = [
        Self::Namespaces,
        Self::Auth,
        Self::Engines,
        Self::Database,
        Self::RaftAdmin,
    ];
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Namespaces => "namespaces",
            Self::Auth => "auth",
            Self::Engines => "engines",
            Self::Database => "database",
            Self::RaftAdmin => "raft_admin",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MountScope {
    pub namespace: String,
    pub mount: String,
    pub incarnation: u64,
}
impl Drop for MountScope {
    fn drop(&mut self) {
        self.namespace.zeroize();
        self.mount.zeroize();
    }
}
impl MountScope {
    pub(crate) fn validate(&self) -> Result<(), RootError> {
        Kv1Key::new(&self.namespace, &self.mount, self.incarnation, "scope")
            .map(|_| ())
            .map_err(|_| RootError::Invalid)
    }
    pub(crate) fn borrowed(&self) -> NativeScope<'_> {
        NativeScope {
            namespace: &self.namespace,
            mount: &self.mount,
            incarnation: self.incarnation,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Kv2GraphRef {
    pub scope: MountScope,
    pub graph_format: String,
    pub root: Kv1Root,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoleOwner {
    pub domain: OwnerDomain,
    pub owner: OpaqueOwnerRef,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReaderFloor {
    pub record_format: u32,
    pub minimum_state_schema: u32,
    pub native_kv2_format: u32,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct AddressMaterial(pub [u8; 32]);
impl Drop for AddressMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordStateRootV6 {
    pub storage_format: String,
    pub state_schema: u32,
    pub reader_floor: ReaderFloor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_lossless_json_format: Option<u32>,
    pub cluster_id: String,
    pub replay_epoch: u64,
    pub owners: [RoleOwner; 5],
    pub kv1: Kv1Root,
    pub kv2: Vec<Kv2GraphRef>,
    pub object_address_key: AddressMaterial,
}
impl std::fmt::Debug for RecordStateRootV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordStateRootV6")
            .field("state_schema", &self.state_schema)
            .field("replay_epoch", &self.replay_epoch)
            .field("kv2_mounts", &self.kv2.len())
            .field("object_address_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ObjectDomain {
    Owner(OwnerDomain),
    Kv1,
    Kv2(MountScope),
}

fn validate_graph(root: &Kv1Root, required: bool, max_records: u64) -> Result<(), RootError> {
    if root.reference.as_ref().is_some_and(|reference| {
        reference.payload_bytes > crate::state_records::MAX_GRAPH_BYTES as u64
            || reference.record_count > max_records
    }) {
        return Err(RootError::TooLarge);
    }
    match &root.reference {
        None if !required && root.height == 0 => Ok(()),
        Some(reference)
            if (1..=16).contains(&root.height)
                && reference.encoded_bytes > 0
                && reference.encoded_bytes as usize <= crate::state_records::PAGE_BYTES
                && reference.record_count > 0
                && reference.payload_bytes > 0
                && ((root.height == 1
                    && matches!(reference.kind, ObjectKind::Leaf | ObjectKind::PackedLeaf))
                    || root.height > 1 && reference.kind == ObjectKind::Branch) =>
        {
            Ok(())
        }
        _ => Err(RootError::Invalid),
    }
}

impl RecordStateRootV6 {
    pub(crate) fn validate(&self) -> Result<(), RootError> {
        if self.storage_format != STORAGE_FORMAT
            || self.object_address_key.0 == [0; 32]
            || self.cluster_id.is_empty()
            || self.cluster_id.len() > 256
            || self.cluster_id.bytes().any(|byte| byte.is_ascii_control())
            || self.reader_floor.record_format != READER_FORMAT
            || self.reader_floor.native_kv2_format != 1
            || self.reader_floor.minimum_state_schema < 36
            || self.state_schema < self.reader_floor.minimum_state_schema
            || self.global_lossless_json_format.is_some_and(|format| {
                format != 1 || self.state_schema < crate::service::GLOBAL_LOSSLESS_JSON_STATE_SCHEMA
            })
        {
            return Err(RootError::Invalid);
        }
        let mut total = 0_u64;
        for (role, expected) in self.owners.iter().zip(OwnerDomain::ALL) {
            let owner = &role.owner;
            if role.domain != expected
                || owner.name != expected.name()
                || owner.total_bytes == 0
                || owner.chunks.is_empty()
            {
                return Err(RootError::Invalid);
            }
            if owner.total_bytes > crate::MAX_APPLICATION_STATE_BYTES as u64
                || owner.chunks.len()
                    > crate::MAX_APPLICATION_STATE_BYTES
                        .div_ceil(crate::state_record_root::OWNER_CHUNK_BYTES)
            {
                return Err(RootError::TooLarge);
            }
            let mut sum = 0_u64;
            for chunk in &owner.chunks {
                if chunk.kind != ObjectKind::OwnerChunk
                    || chunk.record_count != 0
                    || chunk.payload_bytes == 0
                    || chunk.payload_bytes > crate::state_record_root::OWNER_CHUNK_BYTES as u64
                    || u64::from(chunk.encoded_bytes) != chunk.payload_bytes + 25
                {
                    return Err(RootError::Invalid);
                }
                sum = sum
                    .checked_add(chunk.payload_bytes)
                    .ok_or(RootError::TooLarge)?;
            }
            if sum != owner.total_bytes {
                return Err(RootError::Invalid);
            }
            total = total.checked_add(sum).ok_or(RootError::TooLarge)?;
        }
        if total > crate::MAX_APPLICATION_STATE_BYTES as u64 || self.kv2.len() > MAX_KV2_MOUNTS {
            return Err(RootError::TooLarge);
        }
        validate_graph(&self.kv1, false, MAX_KV1_RECORDS)?;
        let mut mounts = BTreeSet::new();
        let mut prior = None;
        let mut payload = 0_u64;
        let mut records = 0_u64;
        for graph in &self.kv2 {
            graph.scope.validate()?;
            if graph.graph_format != crate::engines::kv2_native_records::NATIVE_FORMAT
                || prior.is_some_and(|scope| scope >= &graph.scope)
                || !mounts.insert((&graph.scope.namespace, &graph.scope.mount))
            {
                return Err(RootError::Invalid);
            }
            validate_graph(&graph.root, true, MAX_KV2_RECORDS)?;
            payload = payload
                .checked_add(
                    graph
                        .root
                        .reference
                        .as_ref()
                        .ok_or(RootError::Invalid)?
                        .payload_bytes,
                )
                .ok_or(RootError::TooLarge)?;
            prior = Some(&graph.scope);
            records = records
                .checked_add(
                    graph
                        .root
                        .reference
                        .as_ref()
                        .ok_or(RootError::Invalid)?
                        .record_count,
                )
                .ok_or(RootError::TooLarge)?;
        }
        if payload > crate::state_records::MAX_GRAPH_BYTES as u64 || records > MAX_KV2_RECORDS {
            return Err(RootError::TooLarge);
        }
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
    pub(crate) fn key(&self, domain: &[u8]) -> Result<Arc<AddressKey>, RootError> {
        let base = AddressKey::from_bytes(self.object_address_key.0);
        let mut key = base
            .digest(domain, self.cluster_id.as_bytes())
            .map_err(|_| RootError::Authentication)?;
        let result = AddressKey::from_bytes(key);
        key.zeroize();
        Ok(result)
    }
    pub(crate) fn owner_key(&self, domain: OwnerDomain) -> Result<Arc<AddressKey>, RootError> {
        self.key(format!("state-v6/owner-objects/{}", domain.name()).as_bytes())
    }
    pub(crate) fn kv1_key(&self) -> Result<Arc<AddressKey>, RootError> {
        self.key(b"state-v6/kv1-objects")
    }
    pub(crate) fn kv2_parent_key(&self) -> Result<Arc<AddressKey>, RootError> {
        self.key(b"state-v6/kv2-parent")
    }
    pub(crate) fn owner_digest(
        &self,
        domain: OwnerDomain,
        bytes: &[u8],
    ) -> Result<[u8; 32], RootError> {
        self.owner_key(domain)?
            .digest(b"state-v6/owner-canonical", bytes)
            .map_err(|_| RootError::Authentication)
    }
    pub(crate) fn identity(&self) -> Result<StateIdentity, RootError> {
        let bytes = self.encode()?;
        let key = self.key(b"state-v6/root-identity-key")?;
        Ok(StateIdentity::RecordsV6(
            key.digest(b"state-root-v6", &bytes)
                .map_err(|_| RootError::Authentication)?,
        ))
    }
    pub(crate) fn references(&self) -> impl Iterator<Item = &ObjectRef> {
        self.owners
            .iter()
            .flat_map(|role| role.owner.chunks.iter())
            .chain(self.kv1.reference.iter())
            .chain(
                self.kv2
                    .iter()
                    .flat_map(|graph| graph.root.reference.iter()),
            )
    }
}
