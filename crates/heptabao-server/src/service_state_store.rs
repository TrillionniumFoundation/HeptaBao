//! Versioned chunk framing for the authoritative server state.
//!
//! `system/state` is either a legacy serialized State value or a small manifest.
//! V1 writers alternated between two bounded slots. V2 uses content-addressed
//! chunks: unchanged chunks are referenced by the next manifest without another
//! durable write, replaced chunks are deleted in the same atomic batch, and the
//! manifest remains the sole publication point. Readers admit legacy JSON, V1
//! slot manifests, and V2 content-addressed manifests.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::fmt;

const STATE_STORAGE_FORMAT_V1: &str = "heptabao-state-chunks-v1";
pub(crate) const STATE_STORAGE_FORMAT: &str = "heptabao-state-chunks-v2";
pub(crate) const STATE_CHUNK_BYTES: usize = 512 * 1024;
pub(crate) const MAX_SERIALIZED_STATE_BYTES: usize = crate::MAX_APPLICATION_STATE_BYTES;
pub(crate) const MAX_STATE_CHUNKS: usize = MAX_SERIALIZED_STATE_BYTES / STATE_CHUNK_BYTES;
const STATE_SLOT_COUNT: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateManifest {
    storage_format: String,
    manifest_schema: u32,
    state_schema: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slot: Option<u8>,
    revision: String,
    total_bytes: u64,
    chunk_bytes: u32,
    chunk_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chunks: Vec<String>,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateChunk {
    pub resource: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateWritePlan {
    /// New content-addressed chunks that do not already belong to the current
    /// manifest generation.
    pub chunks: Vec<StateChunk>,
    /// Chunks referenced by the current V2 manifest and reused by the next one.
    pub required_existing: Vec<String>,
    /// Previous-generation chunks no longer referenced by the next manifest.
    pub deletes: Vec<String>,
    pub manifest_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StateStoreError {
    EmptyState,
    StateTooLarge,
    InvalidOperationId,
    InvalidManifest,
    InvalidChunk,
    DigestMismatch,
    Serialization,
}

impl fmt::Display for StateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyState => "server state is empty",
            Self::StateTooLarge => "server state exceeds the chunked storage bound",
            Self::InvalidOperationId => "server state operation identity is invalid",
            Self::InvalidManifest => "server state manifest is invalid",
            Self::InvalidChunk => "server state chunk set is invalid",
            Self::DigestMismatch => "server state chunks do not match the manifest digest",
            Self::Serialization => "server state manifest serialization failed",
        })
    }
}

impl std::error::Error for StateStoreError {}

impl StateManifest {
    fn validate(&self) -> Result<(), StateStoreError> {
        let total_bytes =
            usize::try_from(self.total_bytes).map_err(|_| StateStoreError::InvalidManifest)?;
        let chunk_bytes =
            usize::try_from(self.chunk_bytes).map_err(|_| StateStoreError::InvalidManifest)?;
        let chunk_count =
            usize::try_from(self.chunk_count).map_err(|_| StateStoreError::InvalidManifest)?;
        if self.state_schema == 0
            || total_bytes == 0
            || total_bytes > MAX_SERIALIZED_STATE_BYTES
            || chunk_bytes != STATE_CHUNK_BYTES
            || chunk_count == 0
            || chunk_count > MAX_STATE_CHUNKS
            || chunk_count != total_bytes.div_ceil(STATE_CHUNK_BYTES)
            || !is_lower_hex(&self.revision, 64)
            || !is_lower_hex(&self.sha256, 64)
        {
            return Err(StateStoreError::InvalidManifest);
        }
        match self.storage_format.as_str() {
            STATE_STORAGE_FORMAT_V1 => {
                if self.manifest_schema != 1
                    || self.slot.is_none_or(|slot| slot >= STATE_SLOT_COUNT)
                    || !self.chunks.is_empty()
                {
                    return Err(StateStoreError::InvalidManifest);
                }
            }
            STATE_STORAGE_FORMAT => {
                if self.manifest_schema != 2
                    || self.slot.is_some()
                    || self.chunks.len() != chunk_count
                    || self
                        .chunks
                        .iter()
                        .any(|digest| !is_lower_hex(digest, 64))
                {
                    return Err(StateStoreError::InvalidManifest);
                }
            }
            _ => return Err(StateStoreError::InvalidManifest),
        }
        Ok(())
    }

    pub fn state_schema(&self) -> u32 {
        self.state_schema
    }

    #[cfg(test)]
    pub fn storage_format(&self) -> &str {
        &self.storage_format
    }

    #[cfg(test)]
    pub fn slot(&self) -> Option<u8> {
        self.slot
    }

    #[cfg(test)]
    pub fn next_slot(&self) -> u8 {
        self.slot.map_or(0, |slot| (slot + 1) % STATE_SLOT_COUNT)
    }

    pub fn chunk_count(&self) -> usize {
        usize::try_from(self.chunk_count).unwrap_or(0)
    }

    pub fn chunk_resource(&self, index: usize) -> Result<String, StateStoreError> {
        if index >= self.chunk_count() {
            return Err(StateStoreError::InvalidChunk);
        }
        match self.storage_format.as_str() {
            STATE_STORAGE_FORMAT_V1 => Ok(slot_chunk_resource(
                self.slot.ok_or(StateStoreError::InvalidManifest)?,
                index,
            )),
            STATE_STORAGE_FORMAT => Ok(digest_chunk_resource(
                self.chunks
                    .get(index)
                    .ok_or(StateStoreError::InvalidChunk)?,
            )),
            _ => Err(StateStoreError::InvalidManifest),
        }
    }

    pub fn unique_chunk_resources(&self) -> Result<std::collections::BTreeSet<String>, StateStoreError> {
        (0..self.chunk_count())
            .map(|index| self.chunk_resource(index))
            .collect()
    }
}

impl StateWritePlan {
    pub fn new(
        bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        previous: Option<&StateManifest>,
    ) -> Result<Self, StateStoreError> {
        if bytes.is_empty() {
            return Err(StateStoreError::EmptyState);
        }
        if bytes.len() > MAX_SERIALIZED_STATE_BYTES {
            return Err(StateStoreError::StateTooLarge);
        }
        if operation_id.is_empty()
            || operation_id.len() > 192
            || !operation_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(StateStoreError::InvalidOperationId);
        }
        if state_schema == 0 {
            return Err(StateStoreError::InvalidManifest);
        }
        if let Some(manifest) = previous {
            manifest.validate()?;
        }

        let revision = hex(&crypto::digest(operation_id.as_bytes()));
        let previous_resources = previous
            .map(StateManifest::unique_chunk_resources)
            .transpose()?
            .unwrap_or_default();
        let mut chunk_digests = Vec::with_capacity(bytes.len().div_ceil(STATE_CHUNK_BYTES));
        let mut chunks = std::collections::BTreeMap::<String, Vec<u8>>::new();
        let mut required_existing = std::collections::BTreeSet::new();
        for chunk in bytes.chunks(STATE_CHUNK_BYTES) {
            let digest = hex(&crypto::digest(chunk));
            let resource = digest_chunk_resource(&digest);
            chunk_digests.push(digest);
            if previous_resources.contains(&resource) {
                required_existing.insert(resource);
            } else {
                chunks.entry(resource).or_insert_with(|| chunk.to_vec());
            }
        }
        let next_resources = chunk_digests
            .iter()
            .map(|digest| digest_chunk_resource(digest))
            .collect::<std::collections::BTreeSet<_>>();
        let deletes = previous_resources
            .difference(&next_resources)
            .cloned()
            .collect::<Vec<_>>();

        let manifest = StateManifest {
            storage_format: STATE_STORAGE_FORMAT.to_owned(),
            manifest_schema: 2,
            state_schema,
            slot: None,
            revision,
            total_bytes: u64::try_from(bytes.len()).map_err(|_| StateStoreError::StateTooLarge)?,
            chunk_bytes: u32::try_from(STATE_CHUNK_BYTES)
                .map_err(|_| StateStoreError::InvalidManifest)?,
            chunk_count: u32::try_from(chunk_digests.len())
                .map_err(|_| StateStoreError::InvalidManifest)?,
            chunks: chunk_digests,
            sha256: hex(&crypto::digest(bytes)),
        };
        manifest.validate()?;
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|_| StateStoreError::Serialization)?;
        Ok(Self {
            chunks: chunks
                .into_iter()
                .map(|(resource, bytes)| StateChunk { resource, bytes })
                .collect(),
            required_existing: required_existing.into_iter().collect(),
            deletes,
            manifest_bytes,
        })
    }

    pub fn required_mutations(&self) -> usize {
        self.chunks
            .len()
            .saturating_add(self.deletes.len())
            .saturating_add(1)
    }
}


/// Detect a chunked-state manifest without mistaking a legacy State JSON object
/// for one. Once the storage-format discriminator is present, malformed or
/// unsupported content fails closed instead of falling back to legacy parsing.
pub(crate) fn decode_manifest(bytes: &[u8]) -> Result<Option<StateManifest>, StateStoreError> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    if !object.contains_key("storage_format") {
        return Ok(None);
    }
    let manifest: StateManifest =
        serde_json::from_value(value).map_err(|_| StateStoreError::InvalidManifest)?;
    manifest.validate()?;
    Ok(Some(manifest))
}

#[cfg(test)]
pub(crate) fn next_slot(current_state_record: &[u8]) -> Result<u8, StateStoreError> {
    Ok(match decode_manifest(current_state_record)? {
        Some(manifest) => manifest.next_slot(),
        None => 0,
    })
}

pub(crate) fn assemble_state(
    manifest: &StateManifest,
    chunks: &[&[u8]],
) -> Result<Vec<u8>, StateStoreError> {
    manifest.validate()?;
    if chunks.len() != manifest.chunk_count() {
        return Err(StateStoreError::InvalidChunk);
    }
    let total =
        usize::try_from(manifest.total_bytes).map_err(|_| StateStoreError::InvalidManifest)?;
    let mut state = Vec::with_capacity(total);
    for (index, chunk) in chunks.iter().enumerate() {
        let last = index + 1 == chunks.len();
        if chunk.is_empty()
            || (!last && chunk.len() != STATE_CHUNK_BYTES)
            || chunk.len() > STATE_CHUNK_BYTES
        {
            return Err(StateStoreError::InvalidChunk);
        }
        state.extend_from_slice(chunk);
        if state.len() > total {
            return Err(StateStoreError::InvalidChunk);
        }
    }
    if state.len() != total || hex(&crypto::digest(&state)) != manifest.sha256 {
        return Err(StateStoreError::DigestMismatch);
    }
    Ok(state)
}

fn slot_chunk_resource(slot: u8, index: usize) -> String {
    format!("state-chunks/{slot}/{index:04}")
}

fn digest_chunk_resource(digest: &str) -> String {
    format!("state-chunks/by-digest/{digest}")
}

pub(crate) fn validate_content_addressed_chunk(
    resource: &str,
    bytes: &[u8],
) -> Result<(), StateStoreError> {
    let digest = resource
        .strip_prefix("state-chunks/by-digest/")
        .ok_or(StateStoreError::InvalidChunk)?;
    if !is_lower_hex(digest, 64) || hex(&crypto::digest(bytes)) != digest {
        return Err(StateStoreError::DigestMismatch);
    }
    Ok(())
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

    #[test]
    fn one_chunk_plan_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let state = br#"{"schema":5,"value":"small"}"#;
        let plan =
            StateWritePlan::new(state, "0123456789abcdef0123456789abcdef", 5, None)?;
        assert_eq!(plan.required_mutations(), 2);
        assert!(plan.required_existing.is_empty());
        assert!(plan.deletes.is_empty());
        let manifest = decode_manifest(&plan.manifest_bytes)?.ok_or("manifest missing")?;
        assert_eq!(manifest.storage_format(), STATE_STORAGE_FORMAT);
        assert_eq!(manifest.slot(), None);
        let chunks = plan
            .chunks
            .iter()
            .map(|chunk| chunk.bytes.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(assemble_state(&manifest, &chunks)?, state);
        Ok(())
    }

    #[test]
    fn content_addressed_plan_reuses_unchanged_chunks_and_deletes_replaced_chunks()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = vec![0x5a; STATE_CHUNK_BYTES + 17];
        let first = StateWritePlan::new(&state, "op-1", 5, None)?;
        let first_manifest = decode_manifest(&first.manifest_bytes)?.ok_or("manifest missing")?;
        assert_eq!(first.chunks.len(), 2);
        assert_eq!(first.required_mutations(), 3);

        let mut changed = state.clone();
        *changed.last_mut().ok_or("state unexpectedly empty")? = 0x6b;
        let second = StateWritePlan::new(&changed, "op-2", 5, Some(&first_manifest))?;
        let second_manifest = decode_manifest(&second.manifest_bytes)?.ok_or("manifest missing")?;
        assert_eq!(second_manifest.storage_format(), STATE_STORAGE_FORMAT);
        assert_eq!(second.chunks.len(), 1);
        assert_eq!(second.required_existing.len(), 1);
        assert_eq!(second.deletes.len(), 1);
        assert_eq!(second.required_mutations(), 3);
        assert_ne!(second.deletes[0], second.chunks[0].resource);
        Ok(())
    }

    #[test]
    fn v1_slot_manifest_remains_readable_for_online_upgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = hex(&crypto::digest(b"legacy-revision"));
        let state_digest = hex(&crypto::digest(b"legacy-state"));
        let manifest = serde_json::json!({
            "storage_format": STATE_STORAGE_FORMAT_V1,
            "manifest_schema": 1,
            "state_schema": 5,
            "slot": 1,
            "revision": revision,
            "total_bytes": 17,
            "chunk_bytes": STATE_CHUNK_BYTES,
            "chunk_count": 1,
            "sha256": state_digest
        });
        let bytes = serde_json::to_vec(&manifest)?;
        let decoded = decode_manifest(&bytes)?.ok_or("manifest missing")?;
        assert_eq!(decoded.slot(), Some(1));
        assert_eq!(decoded.next_slot(), 0);
        assert_eq!(decoded.chunk_resource(0)?, "state-chunks/1/0000");
        Ok(())
    }

    #[test]
    fn legacy_json_selects_initial_slot() -> Result<(), Box<dyn std::error::Error>> {
        let legacy = br#"{"schema":5,"cluster_id":"legacy"}"#;
        assert!(decode_manifest(legacy)?.is_none());
        assert_eq!(next_slot(legacy)?, 0);
        Ok(())
    }

    #[test]
    fn manifest_tampering_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let state = vec![7_u8; STATE_CHUNK_BYTES + 1];
        let plan = StateWritePlan::new(&state, "op-2", 5, None)?;
        let manifest = decode_manifest(&plan.manifest_bytes)?.ok_or("manifest missing")?;
        let mut owned_chunks = plan
            .chunks
            .iter()
            .map(|chunk| chunk.bytes.clone())
            .collect::<Vec<_>>();
        owned_chunks[1][0] ^= 1;
        let chunks = owned_chunks.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            assemble_state(&manifest, &chunks),
            Err(StateStoreError::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn content_addressed_chunk_name_binds_payload() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = b"chunk";
        let digest = hex(&crypto::digest(bytes));
        let resource = digest_chunk_resource(&digest);
        validate_content_addressed_chunk(&resource, bytes)?;
        assert_eq!(
            validate_content_addressed_chunk(&resource, b"tampered"),
            Err(StateStoreError::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn oversized_state_is_rejected_before_staging() {
        let state = vec![1_u8; MAX_SERIALIZED_STATE_BYTES + 1];
        assert_eq!(
            StateWritePlan::new(&state, "op-3", 5, None),
            Err(StateStoreError::StateTooLarge)
        );
    }
}
