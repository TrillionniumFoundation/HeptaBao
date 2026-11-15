//! Read-only validation of the experimental KV2 V6 record format.
//!
//! This API checks caller-supplied bytes in bounded memory. It never opens or
//! writes storage, verifies a committed publication, or grants migration,
//! Service, HA, reader admission, or production V6 authority.
use crate::kv2_v6_record_codec::{MAX_CELL, Scope, decode, encode, key};
use crate::kv2_v6_shard_validator::validate_sharded_trial_index;
use crate::state_records::{AddressKey, Kv1Index, Kv1Key, MAX_GRAPH_BYTES, RecordError};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

const MAX_VALIDATION_RECORDS: usize = 65_536;

/// An encoded experimental record and the independent scope it must match.
#[derive(Clone, Copy)]
pub struct EncodedRecord<'a> {
    pub namespace: &'a str,
    pub mount: &'a str,
    pub incarnation: u64,
    pub path: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    Invalid,
    Corrupt,
    Missing,
    TooLarge,
    Randomness,
}
impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid experimental KV2 record scope",
            Self::Corrupt => "invalid experimental KV2 record format",
            Self::Missing => "experimental KV2 graph is incomplete",
            Self::TooLarge => "experimental KV2 validation capacity exceeded",
            Self::Randomness => "experimental KV2 validation key unavailable",
        })
    }
}
impl std::error::Error for ValidationError {}

fn validation_error(error: RecordError) -> ValidationError {
    match error {
        RecordError::Invalid => ValidationError::Invalid,
        RecordError::Corrupt => ValidationError::Corrupt,
        RecordError::Missing => ValidationError::Missing,
        RecordError::TooLarge => ValidationError::TooLarge,
    }
}

/// Check canonical typed records, duplicate keys and complete trial shard
/// closure. Preflight permits at most 65,536 records, 4 MiB per cell and 64 MiB
/// aggregate raw bytes; the existing encoded graph limit is also 64 MiB.
/// Success describes these supplied bytes only, never durable state or a root.
pub fn validate_trial_records(records: &[EncodedRecord<'_>]) -> Result<(), ValidationError> {
    if records.len() > MAX_VALIDATION_RECORDS {
        return Err(ValidationError::TooLarge);
    }
    let mut raw_bytes = 0_usize;
    for record in records {
        if record.bytes.len() > MAX_CELL {
            return Err(ValidationError::TooLarge);
        }
        raw_bytes = raw_bytes
            .checked_add(record.bytes.len())
            .filter(|total| *total <= MAX_GRAPH_BYTES)
            .ok_or(ValidationError::TooLarge)?;
        if record.mount.len() > 512 {
            return Err(ValidationError::Invalid);
        }
        // Validate borrowed namespace/path bounds before copying any scope or
        // parsing JSON. The generic key constructor checks lengths before its
        // corresponding field allocations and clears its temporary strings.
        Kv1Key::new(
            record.namespace,
            record.mount,
            record.incarnation,
            record.path,
        )
        .map_err(validation_error)?;
    }
    // This private, transient key belongs only to the in-memory validation
    // graph. It is never returned, retained or used for a storage publication.
    let mut address_bytes = Zeroizing::new([0_u8; 32]);
    SystemRandom::new()
        .fill(&mut *address_bytes)
        .map_err(|_| ValidationError::Randomness)?;
    let mut graph = Kv1Index::empty(AddressKey::from_bytes(*address_bytes));
    for record in records {
        let scope = Zeroizing::new(Scope {
            namespace: record.namespace.into(),
            mount: record.mount.into(),
            incarnation: record.incarnation,
            path: record.path.into(),
        });
        let expected = key(&scope).map_err(validation_error)?;
        let cell = decode(&expected, record.bytes).map_err(validation_error)?;
        let (scope, version, entry) = cell.into_parts();
        let canonical = encode(scope, version, entry).map_err(validation_error)?;
        if canonical.as_slice() != record.bytes || graph.get(&expected).is_some() {
            return Err(ValidationError::Corrupt);
        }
        graph = graph
            .edit(expected, Some(record.bytes))
            .map_err(validation_error)?
            .next;
    }
    validate_sharded_trial_index(&graph).map_err(validation_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv2_v6_shard_validator::{SHARD_INDEX_SCHEMA, sharded_version_scope};
    use serde_json::json;

    #[test]
    fn oversized_borrowed_scopes_are_rejected_before_json_parse() {
        let record = EncodedRecord {
            namespace: "tenant",
            mount: "secret/",
            incarnation: 7,
            path: "invoice",
            bytes: b"{}",
        };
        let namespace = "x".repeat(1025);
        let mount = "x".repeat(513);
        let path = "x".repeat(1025);
        for oversized in [
            EncodedRecord {
                namespace: &namespace,
                ..record
            },
            EncodedRecord {
                mount: &mount,
                ..record
            },
            EncodedRecord {
                path: &path,
                ..record
            },
        ] {
            assert_eq!(
                validate_trial_records(&[oversized]),
                Err(ValidationError::Invalid)
            );
        }
    }

    #[test]
    fn record_count_and_aggregate_byte_preflight_precede_json_parse() {
        let record = EncodedRecord {
            namespace: "tenant",
            mount: "secret/",
            incarnation: 7,
            path: "invoice",
            bytes: b"",
        };
        let too_many = vec![record; MAX_VALIDATION_RECORDS + 1];
        assert_eq!(
            validate_trial_records(&too_many),
            Err(ValidationError::TooLarge)
        );
        let bytes = vec![b' '; MAX_CELL];
        let oversized = vec![
            EncodedRecord {
                bytes: &bytes,
                ..record
            };
            MAX_GRAPH_BYTES / MAX_CELL + 1
        ];
        assert_eq!(
            validate_trial_records(&oversized),
            Err(ValidationError::TooLarge)
        );
    }

    #[test]
    fn read_only_validation_rejects_duplicate_scope_and_noncanonical_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = encode(
            Scope {
                namespace: "tenant".into(),
                mount: "secret/".into(),
                incarnation: 7,
                path: "invoice".into(),
            },
            1,
            json!({"current_version":1,"versions":{"1":{"data":{"value":true},"destroyed":false}}}),
        )?;
        let record = EncodedRecord {
            namespace: "tenant",
            mount: "secret/",
            incarnation: 7,
            path: "invoice",
            bytes: &bytes,
        };
        validate_trial_records(&[record])?;
        assert_eq!(
            validate_trial_records(&[record, record]),
            Err(ValidationError::Corrupt)
        );
        assert_eq!(
            validate_trial_records(&[EncodedRecord {
                path: "other",
                ..record
            }]),
            Err(ValidationError::Corrupt)
        );
        let mut noncanonical = bytes.to_vec();
        noncanonical.push(b' ');
        assert_eq!(
            validate_trial_records(&[EncodedRecord {
                bytes: &noncanonical,
                ..record
            }]),
            Err(ValidationError::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn read_only_validation_requires_complete_shard_closure()
    -> Result<(), Box<dyn std::error::Error>> {
        let logical = Scope {
            namespace: "tenant".into(),
            mount: "secret/".into(),
            incarnation: 7,
            path: "invoice".into(),
        };
        let shard_scope = sharded_version_scope(&logical, 1)?;
        let index_bytes = encode(
            logical.clone(),
            1,
            json!({"shard_schema":SHARD_INDEX_SCHEMA,"current_version":1,
                "versions":{"1":{"destroyed":false,"data":{"shard_path":shard_scope.path}}}}),
        )?;
        let shard_bytes = encode(
            shard_scope.clone(),
            1,
            json!({"current_version":1,"versions":{"1":{"destroyed":false,"data":{"payload":"fixture"}}}}),
        )?;
        let index = EncodedRecord {
            namespace: &logical.namespace,
            mount: &logical.mount,
            incarnation: logical.incarnation,
            path: &logical.path,
            bytes: &index_bytes,
        };
        let shard = EncodedRecord {
            namespace: &shard_scope.namespace,
            mount: &shard_scope.mount,
            incarnation: shard_scope.incarnation,
            path: &shard_scope.path,
            bytes: &shard_bytes,
        };
        assert_eq!(
            validate_trial_records(&[index]),
            Err(ValidationError::Missing)
        );
        assert_eq!(
            validate_trial_records(&[shard]),
            Err(ValidationError::Corrupt)
        );
        validate_trial_records(&[index, shard])?;
        Ok(())
    }
}
