//! Pre-admission V6 sharded-record graph *read validation* only.
//!
//! Compiled in ordinary production builds, but not wired to Service, HA,
//! migration or the production KV2 engine. A MAC-authenticated graph is not
//! permission to publish it. The old V5 writer and its 16MiB limit remain.
//! The reserved U+001F physical namespace is private to this QA format.
use crate::kv2_v6_record_codec::{Scope, decode, key};
use crate::state_records::{Kv1Index, RecordError};
use serde_json::Value;

pub(crate) const SHARD_INDEX_SCHEMA: &str = "heptabao-kv2-v6-private-sharded-index-qa-v1";
const SHARD_RESERVED_MOUNT: &str = "\u{001f}shards/";

pub(crate) fn sharded_version_scope(logical: &Scope, version: u64) -> Result<Scope, RecordError> {
    use sha2::{Digest as _, Sha256};
    // The physical domain prefix is always well formed, so validating only
    // the derived shard key would falsely admit an invalid *logical* owner.
    // Bind this shard to a validated original namespace, mount, incarnation,
    // and path before deriving any physical identity.
    key(logical)?;
    // Kv1Key validates NUL, but its generic record namespace may contain
    // other control bytes. Reject the original logical V6 scope before a
    // normalized/hash-derived physical shard could be staged or published.
    if version == 0
        || version > 32
        || logical.namespace.chars().any(char::is_control)
        || logical.mount.chars().any(char::is_control)
        || logical.path.chars().any(char::is_control)
    {
        return Err(RecordError::Invalid);
    }
    let digest = Sha256::digest(logical.path.as_bytes());
    let mut digest_hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut digest_hex, "{byte:02x}").map_err(|_| RecordError::Invalid)?;
    }
    let version_scope = Scope {
        namespace: logical.namespace.clone(),
        mount: format!("{}{}", logical.mount, SHARD_RESERVED_MOUNT),
        incarnation: logical.incarnation,
        path: format!("{digest_hex}/{version:020}"),
    };
    key(&version_scope)?;
    Ok(version_scope)
}

// Audit the complete immutable graph before any staged object or root is
// published, and again after signed-root reopen. A caller must not publish a
// valid MAC with missing/misbound version cells, or smuggle orphan shards.
pub(crate) fn validate_sharded_trial_index(graph: &Kv1Index) -> Result<(), RecordError> {
    let mut referenced = std::collections::BTreeSet::new();
    graph.visit_keys(|record_key| {
        let bytes = graph.get(record_key).ok_or(RecordError::Corrupt)?;
        let cell = decode(record_key, bytes)?;
        // Ordinary sparse KV2 records do not carry shard_schema. They still
        // belong to the authenticated V6 graph: reject invalid *logical*
        // namespace/path control aliases before taking that legacy branch.
        // The reserved U+001F physical mount is checked independently below;
        // this does not grant any shard mount or publication authority.
        if cell.scope.namespace.chars().any(char::is_control)
            || cell.scope.path.chars().any(char::is_control)
        {
            return Err(RecordError::Corrupt);
        }
        let Some(schema) = cell.entry.get("shard_schema") else {
            return Ok(());
        };
        if schema.as_str() != Some(SHARD_INDEX_SCHEMA)
            || cell.scope.mount.contains('\u{001f}')
            || cell.version > 32
        {
            return Err(RecordError::Corrupt);
        }
        // The R740 private shard schema has exactly these three index
        // fields. No unknown authority or retention metadata may piggyback
        // on a valid authenticated pointer under this schema discriminator.
        let index = cell.entry.as_object().ok_or(RecordError::Corrupt)?;
        if index.len() != 3
            || !index.contains_key("shard_schema")
            || !index.contains_key("current_version")
            || !index.contains_key("versions")
        {
            return Err(RecordError::Corrupt);
        }
        let versions = index
            .get("versions")
            .and_then(Value::as_object)
            .ok_or(RecordError::Corrupt)?;
        if versions.len() != cell.version as usize {
            return Err(RecordError::Corrupt);
        }
        for version in 1..=cell.version {
            let expected_scope = sharded_version_scope(&cell.scope, version)?;
            let pointer = versions
                .get(&version.to_string())
                .and_then(Value::as_object)
                .ok_or(RecordError::Corrupt)?;
            if pointer.len() != 2 || pointer.get("destroyed") != Some(&Value::Bool(false)) {
                return Err(RecordError::Corrupt);
            }
            let pointer_data = pointer
                .get("data")
                .and_then(Value::as_object)
                .ok_or(RecordError::Corrupt)?;
            if pointer_data.len() != 1 {
                return Err(RecordError::Corrupt);
            }
            let actual_pointer = pointer_data
                .get("shard_path")
                .and_then(Value::as_str)
                .ok_or(RecordError::Corrupt)?;
            if actual_pointer != expected_scope.path {
                return Err(RecordError::Corrupt);
            }
            let actual_key = key(&expected_scope)?;
            let raw = graph.get(&actual_key).ok_or(RecordError::Missing)?;
            let version_cell = decode(&actual_key, raw)?;
            let shard = version_cell.entry.as_object().ok_or(RecordError::Corrupt)?;
            let shards_versions = shard
                .get("versions")
                .and_then(Value::as_object)
                .ok_or(RecordError::Corrupt)?;
            let shard_version = shards_versions
                .get(&version.to_string())
                .and_then(Value::as_object)
                .ok_or(RecordError::Corrupt)?;
            let shard_data = shard_version
                .get("data")
                .and_then(Value::as_object)
                .ok_or(RecordError::Corrupt)?;
            // For this test-only v1 format, one physical shard is precisely
            // one immutable payload, not a carrier for optional authority.
            if version_cell.scope != expected_scope
                || version_cell.version != version
                || shard.len() != 2
                || !shard.contains_key("current_version")
                || !shard.contains_key("versions")
                || shards_versions.len() != 1
                || shard_version.len() != 2
                || shard_version.get("destroyed") != Some(&Value::Bool(false))
                || shard_data.len() != 1
                || shard_data.get("payload").and_then(Value::as_str).is_none()
            {
                return Err(RecordError::Corrupt);
            }
            referenced.insert(actual_key);
        }
        Ok(())
    })?;
    graph.visit_keys(|key| {
        // A signed but unreferenced control-character mount is never an
        // ordinary logical KV2 record. Only version keys named by an
        // authenticated logical pointer may enter the private shard domain.
        // Reject all controls, not only the exact U+001F shard suffix.
        if key.mount().chars().any(char::is_control) && !referenced.contains(key) {
            return Err(RecordError::Corrupt);
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sharded_version_scope_rejects_unauthorized_logical_scope() -> Result<(), RecordError> {
        let logical = Scope {
            namespace: "tenant".into(),
            mount: "secret/".into(),
            incarnation: 7,
            path: "known".into(),
        };
        assert!(sharded_version_scope(&logical, 1).is_ok());
        for invalid in [
            Scope {
                mount: String::new(),
                ..logical.clone()
            },
            Scope {
                mount: "secret".into(),
                ..logical.clone()
            },
            Scope {
                mount: "@reserved/".into(),
                ..logical.clone()
            },
            Scope {
                incarnation: 0,
                ..logical.clone()
            },
            Scope {
                path: String::new(),
                ..logical.clone()
            },
        ] {
            assert!(
                sharded_version_scope(&invalid, 1).is_err(),
                "never derive physical shard identity from invalid logical scope"
            );
        }
        assert!(sharded_version_scope(&logical, 0).is_err());
        assert!(sharded_version_scope(&logical, 33).is_err());
        let first = key(&sharded_version_scope(&logical, 1)?)?;
        let second = key(&sharded_version_scope(&logical, 2)?)?;
        assert!(first != second, "version physical identifiers must differ");
        Ok(())
    }

    // Ordinary Kv1Key admits non-NUL control characters, but a V6 logical
    // owner must never derive an apparently safe physical shard from one.
    // Reject BEFORE stage() can write a shard or signed-root publication.
    #[test]
    fn shard_scope_rejects_control_character_aliases_before_staging() {
        let base = Scope {
            namespace: "tenant".into(),
            mount: "secret/".into(),
            incarnation: 7,
            path: "invoice".into(),
        };
        for invalid in [
            Scope {
                namespace: "tenant\u{0002}".into(),
                ..base.clone()
            },
            Scope {
                mount: "secret/\u{0001}alias/".into(),
                ..base.clone()
            },
            Scope {
                path: "invoice\u{0003}".into(),
                ..base.clone()
            },
        ] {
            assert!(
                key(&invalid).is_ok(),
                "regression must exercise V6 scope admission, not generic Kv1Key rejection"
            );
            assert!(
                sharded_version_scope(&invalid, 1).is_err(),
                "control-character logical aliases must be stopped before physical staging"
            );
        }
    }
}
