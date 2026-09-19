//! Record-oriented local persistence for authoritative Service owners.
//!
//! V4 keeps the existing logical State and HA digest contract, but local durable
//! publication no longer treats that logical State as one chunk stream. Each
//! independently owned domain is serialized and content-addressed separately;
//! one small manifest is the sole publication point. The existing
//! DurableService atomic batch remains the transaction and replay boundary.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const STATE_STORAGE_FORMAT: &str = "heptabao-state-owners-v4";
pub(crate) const STATE_CHUNK_BYTES: usize = 512 * 1024;
const STATE_CHUNK_MIN_BYTES: usize = 384 * 1024;
const STATE_CHUNK_MAX_BYTES: usize = 768 * 1024;
const STATE_CHUNK_WINDOW_BYTES: usize = 64;
const STATE_CHUNK_MASK: u64 = (1_u64 << 19) - 1;
const MAX_SERIALIZED_STATE_BYTES: usize = crate::MAX_APPLICATION_STATE_BYTES;
const OWNER_NAMES: [&str; 5] = ["namespaces", "auth", "engines", "database", "raft_admin"];
const MAX_OWNER_CHUNKS: usize =
    MAX_SERIALIZED_STATE_BYTES.div_ceil(STATE_CHUNK_MIN_BYTES) + OWNER_NAMES.len();

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDescriptor {
    name: String,
    total_bytes: u64,
    chunk_count: u32,
    chunks: Vec<String>,
    chunk_sizes: Vec<u32>,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerStateManifest {
    storage_format: String,
    manifest_schema: u32,
    state_schema: u32,
    revision: String,
    cluster_id: String,
    replay_epoch: u64,
    logical_sha256: String,
    owners: Vec<OwnerDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateChunk {
    pub resource: String,
    pub bytes: Vec<u8>,
}

/// The physical write set for one owner publication.
///
/// This is deliberately derived from the authenticated owner descriptors,
/// rather than from the caller's reuse hint.  A caller can therefore inspect
/// the exact changed-owner boundary before committing an atomic batch.  The
/// write set is also useful to HA integrations: a future owner-record
/// proposal can carry only these changed owners while retaining the manifest
/// as the publication point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerWriteSet {
    pub changed_owners: Vec<String>,
    pub reused_owners: Vec<String>,
    pub staged_chunks: usize,
    pub retired_chunks: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerWritePlan {
    pub chunks: Vec<StateChunk>,
    pub required_existing: Vec<String>,
    pub deletes: Vec<String>,
    pub manifest_bytes: Vec<u8>,
    write_set: OwnerWriteSet,
}

impl OwnerWritePlan {
    pub(crate) fn write_set(&self) -> &OwnerWriteSet {
        &self.write_set
    }

    /// Reject a plan whose physical mutations escape the changed-owner set.
    /// This is a cheap structural check, but it prevents a future caller from
    /// accidentally turning an owner-scoped delta back into a whole-state
    /// rewrite by appending an unrelated resource to the batch.
    pub(crate) fn validate_write_set(&self) -> Result<(), OwnerStoreError> {
        let write_set = self.write_set();
        let changed = write_set
            .changed_owners
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let reused = write_set
            .reused_owners
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if changed.len() + reused.len() != OWNER_NAMES.len()
            || changed.intersection(&reused).next().is_some()
            || changed
                .iter()
                .chain(reused.iter())
                .any(|name| !OWNER_NAMES.contains(name))
            || write_set.staged_chunks != self.chunks.len()
            || write_set.retired_chunks != self.deletes.len()
        {
            return Err(OwnerStoreError::InvalidOwner);
        }
        for resource in self.chunks.iter().map(|chunk| chunk.resource.as_str()) {
            let owner = resource
                .strip_prefix("state-owners/")
                .and_then(|suffix| suffix.split_once('/'))
                .map(|(owner, _)| owner)
                .ok_or(OwnerStoreError::InvalidChunk)?;
            if !changed.contains(owner) {
                return Err(OwnerStoreError::InvalidOwner);
            }
        }
        // The first V4 publication may atomically retire V1/V2/V3 chunks.
        // Those legacy resources are intentionally outside the owner prefix;
        // they are migration cleanup, not an owner write.
        for resource in &self.deletes {
            if resource.starts_with("state-chunks/") {
                continue;
            }
            let owner = resource
                .strip_prefix("state-owners/")
                .and_then(|suffix| suffix.split_once('/'))
                .map(|(owner, _)| owner)
                .ok_or(OwnerStoreError::InvalidChunk)?;
            if !changed.contains(owner) {
                return Err(OwnerStoreError::InvalidOwner);
            }
        }
        Ok(())
    }
}

/// The immutable identity that local owner publication and the HA manifest
/// must share for one logical state commit.  This does not authorize either
/// side by itself; it only makes the cross-layer binding explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerPublicationBinding {
    operation_digest: [u8; 32],
    logical_digest: [u8; 32],
    logical_bytes: usize,
}

impl OwnerPublicationBinding {
    pub(crate) fn verify(
        self,
        operation_id: &str,
        logical_bytes: &[u8],
    ) -> Result<(), OwnerStoreError> {
        if operation_id.is_empty()
            || operation_id.len() > 192
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || self.logical_bytes != logical_bytes.len()
            || self.operation_digest != crypto::digest(operation_id.as_bytes())
            || self.logical_digest != crypto::digest(logical_bytes)
        {
            return Err(OwnerStoreError::DigestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerStoreError {
    EmptyState,
    StateTooLarge,
    InvalidOperationId,
    InvalidManifest,
    InvalidOwner,
    InvalidChunk,
    DigestMismatch,
    Serialization,
}

impl std::fmt::Display for OwnerStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyState => "server state is empty",
            Self::StateTooLarge => "server state exceeds the owner-store bound",
            Self::InvalidOperationId => "server state operation identity is invalid",
            Self::InvalidManifest => "owner-state manifest is invalid",
            Self::InvalidOwner => "owner-state owner is invalid",
            Self::InvalidChunk => "owner-state chunk set is invalid",
            Self::DigestMismatch => "owner-state digest binding failed",
            Self::Serialization => "owner-state manifest serialization failed",
        })
    }
}

impl std::error::Error for OwnerStoreError {}

impl OwnerStateManifest {
    fn validate(&self) -> Result<(), OwnerStoreError> {
        if self.storage_format != STATE_STORAGE_FORMAT
            || self.manifest_schema != 4
            || self.state_schema == 0
            || self.cluster_id.is_empty()
            || self.cluster_id.len() > 256
            || self.cluster_id.bytes().any(|byte| byte.is_ascii_control())
            || !is_lower_hex(&self.revision, 64)
            || !is_lower_hex(&self.logical_sha256, 64)
            || self.owners.len() != OWNER_NAMES.len()
        {
            return Err(OwnerStoreError::InvalidManifest);
        }
        let mut total = 0_usize;
        let mut chunks = 0_usize;
        for (descriptor, expected_name) in self.owners.iter().zip(OWNER_NAMES) {
            if descriptor.name != expected_name
                || descriptor.total_bytes == 0
                || !is_lower_hex(&descriptor.sha256, 64)
                || descriptor.chunks.len()
                    != usize::try_from(descriptor.chunk_count)
                        .map_err(|_| OwnerStoreError::InvalidManifest)?
                || descriptor.chunk_sizes.len() != descriptor.chunks.len()
                || descriptor.chunks.is_empty()
                || descriptor
                    .chunks
                    .iter()
                    .any(|digest| !is_lower_hex(digest, 64))
            {
                return Err(OwnerStoreError::InvalidManifest);
            }
            let expected_total = usize::try_from(descriptor.total_bytes)
                .map_err(|_| OwnerStoreError::InvalidManifest)?;
            let mut observed_total = 0_usize;
            for (index, size) in descriptor.chunk_sizes.iter().enumerate() {
                let size = usize::try_from(*size).map_err(|_| OwnerStoreError::InvalidManifest)?;
                if size == 0
                    || size > STATE_CHUNK_MAX_BYTES
                    || (index + 1 != descriptor.chunk_sizes.len() && size < STATE_CHUNK_MIN_BYTES)
                {
                    return Err(OwnerStoreError::InvalidManifest);
                }
                observed_total = observed_total
                    .checked_add(size)
                    .ok_or(OwnerStoreError::StateTooLarge)?;
            }
            if observed_total != expected_total {
                return Err(OwnerStoreError::InvalidManifest);
            }
            total = total
                .checked_add(expected_total)
                .ok_or(OwnerStoreError::StateTooLarge)?;
            chunks = chunks
                .checked_add(descriptor.chunks.len())
                .ok_or(OwnerStoreError::StateTooLarge)?;
        }
        if total > MAX_SERIALIZED_STATE_BYTES || chunks > MAX_OWNER_CHUNKS {
            return Err(OwnerStoreError::StateTooLarge);
        }
        Ok(())
    }

    pub(crate) fn state_schema(&self) -> u32 {
        self.state_schema
    }

    pub(crate) fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub(crate) fn replay_epoch(&self) -> u64 {
        self.replay_epoch
    }

    #[cfg(test)]
    pub(crate) fn storage_format(&self) -> &str {
        &self.storage_format
    }

    pub(crate) fn verify_logical(&self, bytes: &[u8]) -> Result<(), OwnerStoreError> {
        self.validate()?;
        if bytes.is_empty()
            || bytes.len() > MAX_SERIALIZED_STATE_BYTES
            || hex(&crypto::digest(bytes)) != self.logical_sha256
        {
            return Err(OwnerStoreError::DigestMismatch);
        }
        Ok(())
    }

    fn owner(&self, name: &str) -> Result<&OwnerDescriptor, OwnerStoreError> {
        self.owners
            .iter()
            .find(|owner| owner.name == name)
            .ok_or(OwnerStoreError::InvalidOwner)
    }

    pub(crate) fn chunk_count(&self, owner: &str) -> Result<usize, OwnerStoreError> {
        let owner = self.owner(owner)?;
        usize::try_from(owner.chunk_count).map_err(|_| OwnerStoreError::InvalidManifest)
    }

    pub(crate) fn chunk_resource(
        &self,
        owner: &str,
        index: usize,
    ) -> Result<String, OwnerStoreError> {
        let descriptor = self.owner(owner)?;
        let digest = descriptor
            .chunks
            .get(index)
            .ok_or(OwnerStoreError::InvalidChunk)?;
        owner_chunk_resource(owner, digest)
    }

    pub(crate) fn unique_chunk_resources(&self) -> Result<BTreeSet<String>, OwnerStoreError> {
        let mut resources = BTreeSet::new();
        for name in OWNER_NAMES {
            for index in 0..self.chunk_count(name)? {
                resources.insert(self.chunk_resource(name, index)?);
            }
        }
        Ok(resources)
    }

    pub(crate) fn assemble_owner(
        &self,
        owner: &str,
        chunks: &[&[u8]],
    ) -> Result<Vec<u8>, OwnerStoreError> {
        self.validate()?;
        let descriptor = self.owner(owner)?;
        if chunks.len() != descriptor.chunks.len() {
            return Err(OwnerStoreError::InvalidChunk);
        }
        let total = usize::try_from(descriptor.total_bytes)
            .map_err(|_| OwnerStoreError::InvalidManifest)?;
        let mut bytes = Vec::with_capacity(total);
        for (index, chunk) in chunks.iter().enumerate() {
            let expected_size = descriptor
                .chunk_sizes
                .get(index)
                .and_then(|size| usize::try_from(*size).ok())
                .ok_or(OwnerStoreError::InvalidChunk)?;
            let expected_digest = descriptor
                .chunks
                .get(index)
                .ok_or(OwnerStoreError::InvalidChunk)?;
            let observed_digest = hex(&crypto::digest(chunk));
            if chunk.len() != expected_size || observed_digest.as_str() != expected_digest.as_str()
            {
                return Err(OwnerStoreError::DigestMismatch);
            }
            bytes.extend_from_slice(chunk);
            if bytes.len() > total {
                return Err(OwnerStoreError::InvalidChunk);
            }
        }
        if bytes.len() != total || hex(&crypto::digest(&bytes)) != descriptor.sha256 {
            return Err(OwnerStoreError::DigestMismatch);
        }
        Ok(bytes)
    }
}

impl OwnerWritePlan {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        logical_bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        cluster_id: &str,
        replay_epoch: u64,
        owners: Vec<(&'static str, Vec<u8>)>,
        previous: Option<&OwnerStateManifest>,
        legacy_deletes: Vec<String>,
    ) -> Result<Self, OwnerStoreError> {
        Self::new_with_reuse(
            logical_bytes,
            operation_id,
            state_schema,
            cluster_id,
            replay_epoch,
            owners
                .into_iter()
                .map(|(name, bytes)| (name, Some(bytes)))
                .collect(),
            previous,
            legacy_deletes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_reuse(
        logical_bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        cluster_id: &str,
        replay_epoch: u64,
        owners: Vec<(&'static str, Option<Vec<u8>>)>,
        previous: Option<&OwnerStateManifest>,
        legacy_deletes: Vec<String>,
    ) -> Result<Self, OwnerStoreError> {
        if logical_bytes.is_empty() {
            return Err(OwnerStoreError::EmptyState);
        }
        if logical_bytes.len() > MAX_SERIALIZED_STATE_BYTES {
            return Err(OwnerStoreError::StateTooLarge);
        }
        if operation_id.is_empty()
            || operation_id.len() > 192
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(OwnerStoreError::InvalidOperationId);
        }
        if state_schema == 0
            || cluster_id.is_empty()
            || cluster_id.len() > 256
            || owners.len() != OWNER_NAMES.len()
            || owners
                .iter()
                .zip(OWNER_NAMES)
                .any(|((name, bytes), expected)| {
                    *name != expected || bytes.as_ref().is_some_and(Vec::is_empty)
                })
        {
            return Err(OwnerStoreError::InvalidOwner);
        }
        if let Some(previous) = previous {
            previous.validate()?;
        }

        let previous_resources = previous
            .map(OwnerStateManifest::unique_chunk_resources)
            .transpose()?
            .unwrap_or_default();
        let mut next_resources = BTreeSet::new();
        let mut required_existing = BTreeSet::new();
        let mut chunks = BTreeMap::<String, Vec<u8>>::new();
        let mut descriptors = Vec::with_capacity(OWNER_NAMES.len());
        let mut owner_total = 0_usize;

        for (name, bytes) in owners {
            let Some(bytes) = bytes else {
                let descriptor = previous
                    .ok_or(OwnerStoreError::InvalidOwner)?
                    .owner(name)?
                    .clone();
                let descriptor_total = usize::try_from(descriptor.total_bytes)
                    .map_err(|_| OwnerStoreError::StateTooLarge)?;
                owner_total = owner_total
                    .checked_add(descriptor_total)
                    .ok_or(OwnerStoreError::StateTooLarge)?;
                for digest in &descriptor.chunks {
                    let resource = owner_chunk_resource(name, digest)?;
                    next_resources.insert(resource.clone());
                    required_existing.insert(resource);
                }
                descriptors.push(descriptor);
                continue;
            };

            owner_total = owner_total
                .checked_add(bytes.len())
                .ok_or(OwnerStoreError::StateTooLarge)?;
            let mut digests = Vec::new();
            let mut sizes = Vec::new();
            for chunk in content_defined_chunks(&bytes) {
                let digest = hex(&crypto::digest(chunk));
                let resource = owner_chunk_resource(name, &digest)?;
                next_resources.insert(resource.clone());
                digests.push(digest);
                sizes.push(u32::try_from(chunk.len()).map_err(|_| OwnerStoreError::InvalidChunk)?);
                if previous_resources.contains(&resource) {
                    required_existing.insert(resource);
                } else {
                    chunks.entry(resource).or_insert_with(|| chunk.to_vec());
                }
            }
            descriptors.push(OwnerDescriptor {
                name: name.to_owned(),
                total_bytes: u64::try_from(bytes.len())
                    .map_err(|_| OwnerStoreError::StateTooLarge)?,
                chunk_count: u32::try_from(digests.len())
                    .map_err(|_| OwnerStoreError::StateTooLarge)?,
                chunks: digests,
                chunk_sizes: sizes,
                sha256: hex(&crypto::digest(&bytes)),
            });
        }
        if owner_total > MAX_SERIALIZED_STATE_BYTES {
            return Err(OwnerStoreError::StateTooLarge);
        }

        let mut deletes = previous_resources
            .difference(&next_resources)
            .cloned()
            .collect::<BTreeSet<_>>();
        for resource in legacy_deletes {
            if !next_resources.contains(&resource) {
                deletes.insert(resource);
            }
        }

        let manifest = OwnerStateManifest {
            storage_format: STATE_STORAGE_FORMAT.to_owned(),
            manifest_schema: 4,
            state_schema,
            revision: hex(&crypto::digest(operation_id.as_bytes())),
            cluster_id: cluster_id.to_owned(),
            replay_epoch,
            logical_sha256: hex(&crypto::digest(logical_bytes)),
            owners: descriptors,
        };
        manifest.validate()?;
        let mut changed_owners = Vec::new();
        let mut reused_owners = Vec::new();
        for name in OWNER_NAMES {
            let next = manifest.owner(name)?;
            if previous
                .and_then(|previous| previous.owner(name).ok())
                .is_some_and(|prior| prior.sha256 == next.sha256)
            {
                reused_owners.push(name.to_owned());
            } else {
                changed_owners.push(name.to_owned());
            }
        }
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|_| OwnerStoreError::Serialization)?;
        let write_set = OwnerWriteSet {
            changed_owners,
            reused_owners,
            staged_chunks: chunks.len(),
            retired_chunks: deletes.len(),
        };
        Ok(Self {
            chunks: chunks
                .into_iter()
                .map(|(resource, bytes)| StateChunk { resource, bytes })
                .collect(),
            required_existing: required_existing.into_iter().collect(),
            deletes: deletes.into_iter().collect(),
            manifest_bytes,
            write_set,
        })
    }

    pub(crate) fn required_mutations(&self) -> usize {
        self.chunks
            .len()
            .saturating_add(self.deletes.len())
            .saturating_add(1)
    }

    /// Bind the local owner manifest to the exact operation and canonical
    /// serialized state that the HA layer is about to seal.  The manifest is
    /// still only a local publication plan; callers must perform their own
    /// atomic commit after the HA commit succeeds.
    pub(crate) fn publication_binding(
        &self,
        operation_id: &str,
        logical_bytes: &[u8],
    ) -> Result<OwnerPublicationBinding, OwnerStoreError> {
        if operation_id.is_empty()
            || operation_id.len() > 192
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(OwnerStoreError::InvalidOperationId);
        }
        let manifest =
            decode_manifest(&self.manifest_bytes)?.ok_or(OwnerStoreError::InvalidManifest)?;
        manifest.verify_logical(logical_bytes)?;
        let operation_digest = crypto::digest(operation_id.as_bytes());
        if manifest.revision != hex(&operation_digest) {
            return Err(OwnerStoreError::DigestMismatch);
        }
        Ok(OwnerPublicationBinding {
            operation_digest,
            logical_digest: crypto::digest(logical_bytes),
            logical_bytes: logical_bytes.len(),
        })
    }
}

pub(crate) fn decode_manifest(bytes: &[u8]) -> Result<Option<OwnerStateManifest>, OwnerStoreError> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    if object
        .get("storage_format")
        .and_then(serde_json::Value::as_str)
        != Some(STATE_STORAGE_FORMAT)
    {
        return Ok(None);
    }
    let manifest: OwnerStateManifest =
        serde_json::from_value(value).map_err(|_| OwnerStoreError::InvalidManifest)?;
    manifest.validate()?;
    Ok(Some(manifest))
}

pub(crate) fn validate_content_addressed_chunk(
    resource: &str,
    bytes: &[u8],
) -> Result<(), OwnerStoreError> {
    let suffix = resource
        .strip_prefix("state-owners/")
        .ok_or(OwnerStoreError::InvalidChunk)?;
    let (owner, digest) = suffix
        .split_once("/by-digest/")
        .ok_or(OwnerStoreError::InvalidChunk)?;
    if !OWNER_NAMES.contains(&owner)
        || !is_lower_hex(digest, 64)
        || hex(&crypto::digest(bytes)) != digest
    {
        return Err(OwnerStoreError::DigestMismatch);
    }
    Ok(())
}

fn owner_chunk_resource(owner: &str, digest: &str) -> Result<String, OwnerStoreError> {
    if !OWNER_NAMES.contains(&owner) || !is_lower_hex(digest, 64) {
        return Err(OwnerStoreError::InvalidOwner);
    }
    Ok(format!("state-owners/{owner}/by-digest/{digest}"))
}

fn content_defined_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    let mut chunks = Vec::new();
    let mut start = 0_usize;
    let mut rolling = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        rolling = rolling.rotate_left(1) ^ chunk_byte_hash(byte);
        if index >= STATE_CHUNK_WINDOW_BYTES {
            rolling ^= chunk_byte_hash(bytes[index - STATE_CHUNK_WINDOW_BYTES])
                .rotate_left((STATE_CHUNK_WINDOW_BYTES % u64::BITS as usize) as u32);
        }
        let length = index + 1 - start;
        if length >= STATE_CHUNK_MIN_BYTES
            && ((rolling & STATE_CHUNK_MASK) == 0 || length >= STATE_CHUNK_MAX_BYTES)
        {
            chunks.push(&bytes[start..=index]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        chunks.push(&bytes[start..]);
    }
    chunks
}

fn chunk_byte_hash(byte: u8) -> u64 {
    let mut value = u64::from(byte).wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn is_lower_hex(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(TABLE[usize::from(byte >> 4)]));
        output.push(char::from(TABLE[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owners(engine: Vec<u8>) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("namespaces", br#"{"next_incarnation":1}"#.to_vec()),
            ("auth", br#"{"tokens":[]}"#.to_vec()),
            ("engines", engine),
            ("database", br#"{"connections":[]}"#.to_vec()),
            ("raft_admin", br#"{"policy":null}"#.to_vec()),
        ]
    }

    #[test]
    fn owner_manifest_round_trips_and_binds_logical_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let plan = OwnerWritePlan::new(
            logical,
            "owner-op-1",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 900 * 1024]),
            None,
            Vec::new(),
        )?;
        let manifest = decode_manifest(&plan.manifest_bytes)?.ok_or("manifest missing")?;
        manifest.verify_logical(logical)?;
        assert_eq!(manifest.storage_format(), STATE_STORAGE_FORMAT);
        assert!(manifest.chunk_count("engines")? >= 2);
        Ok(())
    }

    #[test]
    fn explicit_owner_reuse_carries_previous_descriptor_without_new_chunks()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let first = OwnerWritePlan::new(
            logical,
            "owner-op-1",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 900 * 1024]),
            None,
            Vec::new(),
        )?;
        let manifest = decode_manifest(&first.manifest_bytes)?.ok_or("manifest missing")?;
        let expected_auth = (0..manifest.chunk_count("auth")?)
            .map(|index| manifest.chunk_resource("auth", index))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let expected_database = (0..manifest.chunk_count("database")?)
            .map(|index| manifest.chunk_resource("database", index))
            .collect::<Result<BTreeSet<_>, _>>()?;

        let second = OwnerWritePlan::new_with_reuse(
            logical,
            "owner-op-2",
            9,
            "cluster",
            0,
            vec![
                ("namespaces", Some(br#"{"next_incarnation":2}"#.to_vec())),
                ("auth", None),
                ("engines", Some(vec![b'f'; 900 * 1024])),
                ("database", None),
                ("raft_admin", Some(br#"{"policy":null}"#.to_vec())),
            ],
            Some(&manifest),
            Vec::new(),
        )?;
        let reused = second
            .required_existing
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(expected_auth.is_subset(&reused));
        assert!(expected_database.is_subset(&reused));
        assert!(second.chunks.iter().all(|chunk| {
            !expected_auth.contains(&chunk.resource) && !expected_database.contains(&chunk.resource)
        }));
        Ok(())
    }

    #[test]
    fn changing_one_owner_reuses_unchanged_owner_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let first = OwnerWritePlan::new(
            logical,
            "owner-op-1",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 900 * 1024]),
            None,
            Vec::new(),
        )?;
        let manifest = decode_manifest(&first.manifest_bytes)?.ok_or("manifest missing")?;
        let mut next_engine = vec![b'e'; 900 * 1024];
        *next_engine.last_mut().ok_or("empty engine")? = b'f';
        let second = OwnerWritePlan::new(
            logical,
            "owner-op-2",
            9,
            "cluster",
            0,
            owners(next_engine),
            Some(&manifest),
            Vec::new(),
        )?;
        assert!(second.required_existing.len() >= 4);
        assert!(!second.chunks.is_empty());
        assert_eq!(
            second.write_set().changed_owners,
            vec![String::from("engines")]
        );
        assert_eq!(second.write_set().staged_chunks, second.chunks.len());
        assert_eq!(second.write_set().retired_chunks, second.deletes.len());
        assert_eq!(second.write_set().reused_owners.len(), 4);
        Ok(())
    }

    #[test]
    fn identical_supplied_owner_bytes_are_classified_as_reused()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let first = OwnerWritePlan::new(
            logical,
            "owner-op-identical-1",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 900 * 1024]),
            None,
            Vec::new(),
        )?;
        let manifest = decode_manifest(&first.manifest_bytes)?.ok_or("manifest missing")?;
        // Supplying bytes is allowed when the caller cannot use a pointer
        // reuse hint.  Content identity, not the hint, must determine the
        // physical write set.
        let second = OwnerWritePlan::new(
            logical,
            "owner-op-identical-2",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 900 * 1024]),
            Some(&manifest),
            Vec::new(),
        )?;
        assert!(second.chunks.is_empty());
        assert!(second.deletes.is_empty());
        assert!(second.write_set().changed_owners.is_empty());
        assert_eq!(second.write_set().reused_owners.len(), OWNER_NAMES.len());
        assert_eq!(
            second.required_mutations(),
            1,
            "an identical owner publication must only replace the manifest"
        );
        Ok(())
    }

    #[test]
    fn tampered_owner_chunk_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let plan = OwnerWritePlan::new(
            logical,
            "owner-op-3",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 128]),
            None,
            Vec::new(),
        )?;
        let manifest = decode_manifest(&plan.manifest_bytes)?.ok_or("manifest missing")?;
        let resource = manifest.chunk_resource("engines", 0)?;
        let chunk = plan
            .chunks
            .iter()
            .find(|chunk| chunk.resource == resource)
            .ok_or("chunk missing")?;
        let mut tampered = chunk.bytes.clone();
        tampered[0] ^= 1;
        assert_eq!(
            validate_content_addressed_chunk(&resource, &tampered),
            Err(OwnerStoreError::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn owner_plan_publication_binding_covers_operation_and_logical_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let plan = OwnerWritePlan::new(
            logical,
            "owner-op-binding",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 128]),
            None,
            Vec::new(),
        )?;
        let binding = plan.publication_binding("owner-op-binding", logical)?;
        assert!(binding.verify("owner-op-binding", logical).is_ok());
        assert_eq!(
            binding.verify("owner-op-other", logical),
            Err(OwnerStoreError::DigestMismatch)
        );
        let mut altered = logical.to_vec();
        altered[0] ^= 1;
        assert_eq!(
            binding.verify("owner-op-binding", &altered),
            Err(OwnerStoreError::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn write_set_rejects_a_cross_owner_physical_mutation() -> Result<(), Box<dyn std::error::Error>>
    {
        let logical = br#"{"schema":9,"cluster_id":"cluster"}"#;
        let mut plan = OwnerWritePlan::new(
            logical,
            "owner-op-write-set",
            9,
            "cluster",
            0,
            owners(vec![b'e'; 128]),
            None,
            Vec::new(),
        )?;
        plan.chunks.push(StateChunk {
            resource: "state-owners/auth/by-digest/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            bytes: vec![0],
        });
        assert_eq!(
            plan.validate_write_set(),
            Err(OwnerStoreError::InvalidOwner),
            "an owner plan must not silently expand into a cross-owner rewrite"
        );
        Ok(())
    }
}
