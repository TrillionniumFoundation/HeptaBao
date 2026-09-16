//! Versioned chunk framing for the authoritative server state.
//!
//! `system/state` is either a legacy serialized State value or a small manifest.
//! Chunked writers alternate between two bounded slots and publish the new chunks
//! plus the manifest in one durable-service atomic batch. Readers therefore admit
//! either one complete legacy state or one complete manifest generation.

use crate::crypto;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) const STATE_STORAGE_FORMAT: &str = "heptabao-state-chunks-v1";
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
    slot: u8,
    revision: String,
    total_bytes: u64,
    chunk_bytes: u32,
    chunk_count: u32,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateChunk {
    pub resource: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StateWritePlan {
    pub chunks: Vec<StateChunk>,
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
        if self.storage_format != STATE_STORAGE_FORMAT
            || self.manifest_schema != 1
            || self.state_schema == 0
            || self.slot >= STATE_SLOT_COUNT
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
        Ok(())
    }

    pub fn state_schema(&self) -> u32 {
        self.state_schema
    }

    #[cfg(test)]
    pub fn slot(&self) -> u8 {
        self.slot
    }

    pub fn next_slot(&self) -> u8 {
        (self.slot + 1) % STATE_SLOT_COUNT
    }

    pub fn chunk_count(&self) -> usize {
        usize::try_from(self.chunk_count).unwrap_or(0)
    }

    pub fn chunk_resource(&self, index: usize) -> Result<String, StateStoreError> {
        if index >= self.chunk_count() {
            return Err(StateStoreError::InvalidChunk);
        }
        Ok(chunk_resource(self.slot, index))
    }
}

impl StateWritePlan {
    pub fn new(
        bytes: &[u8],
        operation_id: &str,
        state_schema: u32,
        slot: u8,
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
        if state_schema == 0 || slot >= STATE_SLOT_COUNT {
            return Err(StateStoreError::InvalidManifest);
        }

        let revision = hex(&crypto::digest(operation_id.as_bytes()));
        let mut chunks = Vec::with_capacity(bytes.len().div_ceil(STATE_CHUNK_BYTES));
        for (index, chunk) in bytes.chunks(STATE_CHUNK_BYTES).enumerate() {
            chunks.push(StateChunk {
                resource: chunk_resource(slot, index),
                bytes: chunk.to_vec(),
            });
        }
        let manifest = StateManifest {
            storage_format: STATE_STORAGE_FORMAT.to_owned(),
            manifest_schema: 1,
            state_schema,
            slot,
            revision,
            total_bytes: u64::try_from(bytes.len()).map_err(|_| StateStoreError::StateTooLarge)?,
            chunk_bytes: u32::try_from(STATE_CHUNK_BYTES)
                .map_err(|_| StateStoreError::InvalidManifest)?,
            chunk_count: u32::try_from(chunks.len())
                .map_err(|_| StateStoreError::InvalidManifest)?,
            sha256: hex(&crypto::digest(bytes)),
        };
        manifest.validate()?;
        let manifest_bytes =
            serde_json::to_vec(&manifest).map_err(|_| StateStoreError::Serialization)?;
        Ok(Self {
            chunks,
            manifest_bytes,
        })
    }

    pub fn required_mutations(&self) -> usize {
        self.chunks.len().saturating_add(1)
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

fn chunk_resource(slot: u8, index: usize) -> String {
    format!("state-chunks/{slot}/{index:04}")
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
        let plan = StateWritePlan::new(state, "0123456789abcdef0123456789abcdef", 5, 0)?;
        assert_eq!(plan.required_mutations(), 2);
        let manifest = decode_manifest(&plan.manifest_bytes)?.ok_or("manifest missing")?;
        assert_eq!(manifest.slot(), 0);
        assert_eq!(manifest.next_slot(), 1);
        let chunks = plan
            .chunks
            .iter()
            .map(|chunk| chunk.bytes.as_slice())
            .collect::<Vec<_>>();
        assert_eq!(assemble_state(&manifest, &chunks)?, state);
        Ok(())
    }

    #[test]
    fn alternating_slots_bound_persisted_resources() -> Result<(), Box<dyn std::error::Error>> {
        let state = vec![0x5a; STATE_CHUNK_BYTES + 17];
        let first = StateWritePlan::new(&state, "op-1", 5, 0)?;
        let first_manifest = decode_manifest(&first.manifest_bytes)?.ok_or("manifest missing")?;
        let second = StateWritePlan::new(&state, "op-2", 5, first_manifest.next_slot())?;
        let second_manifest = decode_manifest(&second.manifest_bytes)?.ok_or("manifest missing")?;
        assert_eq!(first_manifest.slot(), 0);
        assert_eq!(second_manifest.slot(), 1);
        assert_ne!(first.chunks[0].resource, second.chunks[0].resource);
        assert_eq!(second_manifest.next_slot(), 0);
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
        let plan = StateWritePlan::new(&state, "op-2", 5, 1)?;
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
    fn oversized_state_is_rejected_before_staging() {
        let state = vec![1_u8; MAX_SERIALIZED_STATE_BYTES + 1];
        assert_eq!(
            StateWritePlan::new(&state, "op-3", 5, 0),
            Err(StateStoreError::StateTooLarge)
        );
    }
}
