//! Explicit authentication profiles for durable migration checkpoints.
//! The v1 checksum format remains readable only through the legacy profile.
//! The v2 HMAC profile never falls back, never writes its key into the journal,
//! and does not claim append-only history or protection against complete rollback.
use super::{
    JournalEnvelope, JournalRecord, MigrationJournalError, sha256_json, validate_id,
    validate_sha256,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::fmt;

const AUTHENTICATED_SCHEMA: &str = "heptabao.migration-journal-authenticated-envelope.v2";
const DOMAIN: &[u8] = b"heptabao.migration-journal.authenticated-envelope.v2\0";

/// Caller-supplied HMAC authority. The journal stores the key ID, never key bytes.
///
/// Provision this 32-byte key outside the migration directory. The caller owns
/// custody/erasure of its input buffer. This type does not promise locked memory,
/// external monotonic anchoring, signatures or authentication of provider receipts.
pub struct MigrationJournalAuthenticator {
    key_id: String,
    key: hmac::Key,
}
impl MigrationJournalAuthenticator {
    pub fn new(key_id: impl Into<String>, material: &[u8]) -> Result<Self, MigrationJournalError> {
        let key_id = key_id.into();
        validate_id(&key_id, "authentication_key_id")?;
        if material.len() != 32 || material.iter().all(|byte| *byte == 0) {
            return Err(MigrationJournalError::InvalidAuthenticationKey);
        }
        Ok(Self {
            key_id,
            key: hmac::Key::new(hmac::HMAC_SHA256, material),
        })
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}
impl fmt::Debug for MigrationJournalAuthenticator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MigrationJournalAuthenticator")
            .field("key_id", &self.key_id)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub(super) enum JournalAuthentication {
    LegacyChecksum,
    Authenticated(MigrationJournalAuthenticator),
}
impl JournalAuthentication {
    pub(super) fn key_id(&self) -> Option<&str> {
        match self {
            Self::LegacyChecksum => None,
            Self::Authenticated(key) => Some(key.key_id()),
        }
    }
    pub(super) fn encode(&self, record: &JournalRecord) -> Result<Vec<u8>, MigrationJournalError> {
        match self {
            Self::LegacyChecksum => Ok(serde_json::to_vec(&JournalEnvelope::new(record.clone())?)?),
            Self::Authenticated(authenticator) => {
                let unsigned = AuthenticatedPayload {
                    schema: AUTHENTICATED_SCHEMA.to_owned(),
                    key_id: authenticator.key_id.clone(),
                    payload_sha256: sha256_json(record)?,
                    payload: record.clone(),
                };
                let message = signing_message(&unsigned)?;
                let tag = hmac::sign(&authenticator.key, &message);
                let envelope = AuthenticatedEnvelope {
                    unsigned,
                    hmac_sha256: hex_tag(tag.as_ref()),
                };
                Ok(serde_json::to_vec(&envelope)?)
            }
        }
    }
    pub(super) fn decode(&self, bytes: &[u8]) -> Result<JournalRecord, MigrationJournalError> {
        match self {
            Self::LegacyChecksum => {
                let envelope: JournalEnvelope = serde_json::from_slice(bytes)?;
                envelope.validate()
            }
            Self::Authenticated(authenticator) => {
                // Parse the strict v2 structure directly. An unkeyed v1 object
                // cannot be selected as a valid current or previous generation.
                let envelope: AuthenticatedEnvelope = serde_json::from_slice(bytes)
                    .map_err(|_| MigrationJournalError::AuthenticationFailed)?;
                if envelope.unsigned.schema != AUTHENTICATED_SCHEMA
                    || envelope.unsigned.key_id != authenticator.key_id
                {
                    return Err(MigrationJournalError::AuthenticationFailed);
                }
                let tag = decode_tag(&envelope.hmac_sha256)?;
                let message = signing_message(&envelope.unsigned)?;
                hmac::verify(&authenticator.key, &message, &tag)
                    .map_err(|_| MigrationJournalError::AuthenticationFailed)?;
                validate_sha256(&envelope.unsigned.payload_sha256)?;
                if sha256_json(&envelope.unsigned.payload)? != envelope.unsigned.payload_sha256 {
                    return Err(MigrationJournalError::IntegrityMismatch);
                }
                envelope.unsigned.payload.validate()?;
                Ok(envelope.unsigned.payload)
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedPayload {
    schema: String,
    key_id: String,
    payload_sha256: String,
    payload: JournalRecord,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthenticatedEnvelope {
    unsigned: AuthenticatedPayload,
    hmac_sha256: String,
}
fn signing_message(payload: &AuthenticatedPayload) -> Result<Vec<u8>, MigrationJournalError> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&serde_json::to_vec(payload)?);
    Ok(message)
}
fn hex_tag(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    result
}
fn decode_tag(value: &str) -> Result<[u8; 32], MigrationJournalError> {
    validate_sha256(value).map_err(|_| MigrationJournalError::AuthenticationFailed)?;
    let mut tag = [0; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digits =
            std::str::from_utf8(pair).map_err(|_| MigrationJournalError::AuthenticationFailed)?;
        tag[index] = u8::from_str_radix(digits, 16)
            .map_err(|_| MigrationJournalError::AuthenticationFailed)?;
    }
    Ok(tag)
}
