//! Compiled, read-only KV2 V6 typed-record codec (pre-admission).
//!
//! This module is built in ordinary binaries to validate the prospective V6
//! type/reader on production toolchains. No Service route, writer, Raft,
//! snapshot publication, migration or fallback is enabled.
//! Existing V5 production state and 16MiB opaque owner limit remain intact.
use crate::state_records::{Kv1Key, RecordError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

pub(crate) const FORMAT: &str = "heptabao-kv2-typed-record-trial-v6";
const MOUNT_DOMAIN: &str = "@heptabao-kv2-v6/";
// A 2560KiB authenticated KV2 write already fits the narrowly scoped 3MiB
// production HTTP ingress. The V6 *trial* also stores an internal typed
// envelope and canonical metadata; give a single trial cell at most 4MiB.
// This changes neither the 16MiB opaque production-owner bound nor the 64MiB
// total authenticated record graph. Retained multi-version large values will
// need version-granular storage before V6 can replace production KV2.
pub(crate) const MAX_CELL: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub(crate) namespace: String,
    pub(crate) mount: String,
    pub(crate) incarnation: u64,
    pub(crate) path: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cell {
    pub(crate) format: String,
    pub(crate) scope: Scope,
    pub(crate) version: u64,
    pub(crate) entry: Value,
}

pub(crate) fn key(scope: &Scope) -> Result<Kv1Key, RecordError> {
    if scope.mount.is_empty()
        || scope.mount.starts_with('@')
        || !scope.mount.ends_with('/')
        || scope.mount.len() > 512
        || scope.incarnation == 0
    {
        return Err(RecordError::Invalid);
    }
    Kv1Key::new(
        &scope.namespace,
        &format!("{MOUNT_DOMAIN}{}", scope.mount),
        scope.incarnation,
        &scope.path,
    )
}

pub(crate) fn encode(
    scope: Scope,
    version: u64,
    entry: Value,
) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    if version == 0 || !entry.is_object() {
        return Err(RecordError::Invalid);
    }
    key(&scope)?;
    let bytes = serde_json::to_vec(&Cell {
        format: FORMAT.into(),
        scope,
        version,
        entry,
    })
    .map_err(|_| RecordError::Invalid)?;
    if bytes.len() > MAX_CELL {
        return Err(RecordError::TooLarge);
    }
    Ok(Zeroizing::new(bytes))
}

// The KV2 API carries RFC3339 times; an empty deletion_time means no
// deletion. Missing/null fields remain valid only for legacy sparse records.
// Do not publish a MAC-authenticated root that could later be misinterpreted
// as an expiration/retention decision.
fn valid_kv2_timestamp(value: Option<&Value>, empty_means_absent: bool) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(stamp)) if stamp.is_empty() => empty_means_absent,
        Some(Value::String(stamp)) => chrono::DateTime::parse_from_rfc3339(stamp).is_ok(),
        _ => false,
    }
}

// Both timestamps may be absent in the older sparse wire format. If both
// are present, compare normalized instants rather than their string offsets.
// This rejects a time-inverted signed tombstone before a V6 root is published.
fn valid_kv2_temporal_order(fields: &serde_json::Map<String, Value>) -> bool {
    let (Some(created), Some(deleted)) = (
        fields.get("created_time").and_then(Value::as_str),
        fields.get("deletion_time").and_then(Value::as_str),
    ) else {
        return true;
    };
    if created.is_empty() || deleted.is_empty() {
        return true; // invalid created_time was rejected by the format gate
    }
    match (
        chrono::DateTime::parse_from_rfc3339(created),
        chrono::DateTime::parse_from_rfc3339(deleted),
    ) {
        (Ok(created), Ok(deleted)) => deleted >= created,
        _ => false,
    }
}

pub(crate) fn decode(expected: &Kv1Key, bytes: &[u8]) -> Result<Cell, RecordError> {
    if bytes.len() > MAX_CELL {
        return Err(RecordError::TooLarge);
    }
    let cell: Cell = serde_json::from_slice(bytes).map_err(|_| RecordError::Corrupt)?;
    // The typed KV2 envelope and its retained history must agree. A valid
    // JSON encoding and keyed page digest do not authorize rewriting an
    // older current_version under a higher outer cell version.
    let versions = cell.entry.get("versions").and_then(Value::as_object);
    let current_entry = cell.entry.get("current_version").and_then(Value::as_u64)
        == Some(cell.version)
        && versions
            .and_then(|history| history.get(&cell.version.to_string()))
            .is_some_and(Value::is_object);
    // The immutable signed root must not authorize versions from the future,
    // aliases such as "03", version zero, overflowed indices or non-record
    // historical entries. Sparse history is legal (prior versions may have
    // been retired before migration); every *retained* name is canonical.
    let canonical_history = versions.is_some_and(|history| {
        history.iter().all(|(name, record)| {
            let Some(version_fields) = record.as_object() else {
                return false;
            };
            let data = version_fields.get("data");
            let destroyed = version_fields.get("destroyed");
            // A signed graph may not turn the typed KV2 data field into an
            // array/scalar, reinterpret a string as the destroyed bit, or
            // retain readable plaintext in an explicitly destroyed version.
            // Missing/NULL fields remain accepted for older sparse records;
            // this is a format integrity check, not a retention grant.
            valid_kv2_timestamp(version_fields.get("created_time"), false)
                && valid_kv2_timestamp(version_fields.get("deletion_time"), true)
                && valid_kv2_temporal_order(version_fields)
                && destroyed.is_none_or(Value::is_boolean)
                && data.is_none_or(|value| value.is_object() || value.is_null())
                && (destroyed != Some(&Value::Bool(true)) || data.is_none_or(Value::is_null))
                && name.parse::<u64>().is_ok_and(|version| {
                    version > 0 && version <= cell.version && version.to_string() == *name
                })
        })
    });
    if cell.format != FORMAT
        || cell.version == 0
        || !current_entry
        || !canonical_history
        || !cell.entry.is_object()
        || key(&cell.scope)
            .as_ref()
            .map_or(true, |actual| actual != expected)
        || serde_json::to_vec(&cell)
            .map_err(|_| RecordError::Corrupt)?
            .as_slice()
            != bytes
    {
        return Err(RecordError::Corrupt);
    }
    Ok(cell)
}
