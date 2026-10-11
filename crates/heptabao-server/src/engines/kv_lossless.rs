//! Closed, bounded KV2 migration input and persisted subsecond history.
//! No clock is sampled here. A service owner must publish the returned candidate
//! once and admit the sticky format through its reader/writer schema floor.
use super::*;
use crate::auth::Timestamp;

const IMPORT_SCHEMA: &str = "openbao270-kv2-lossless-v1";
const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_IMPORT_ENTRIES: usize = 10_000;
const MAX_IMPORT_VERSIONS: usize = 100_000;
const NANOS: u64 = 1_000_000_000;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntryPrecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) created_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) updated_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) versions: BTreeMap<u64, VersionPrecision>,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VersionPrecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) created_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) deletion_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_deletion_at: Option<Timestamp>,
}

pub(super) fn subsecond(at: Timestamp) -> Option<Timestamp> {
    (at.duration_since_epoch().subsec_nanos() != 0).then_some(at)
}

pub(super) fn display_time(seconds: u64, precise: Option<Timestamp>) -> String {
    precise.map_or_else(|| timestamp(seconds), Timestamp::rfc3339)
}

pub(super) fn time_before(now: Timestamp, seconds: u64, precise: Option<Timestamp>) -> bool {
    (now.seconds(), now.duration_since_epoch().subsec_nanos())
        < (
            seconds,
            precise.map_or(0, |at| at.duration_since_epoch().subsec_nanos()),
        )
}

impl EntryPrecision {
    pub(super) fn is_empty(&self) -> bool {
        self.created_at.is_none() && self.updated_at.is_none() && self.versions.is_empty()
    }
    pub(super) fn set_version(&mut self, number: u64, value: VersionPrecision) {
        if value.created_at.is_none()
            && value.deletion_at.is_none()
            && value.source_deletion_at.is_none()
        {
            self.versions.remove(&number);
        } else {
            self.versions.insert(number, value);
        }
    }
}

fn consistent_time(seconds: u64, precise: Option<Timestamp>) -> bool {
    Timestamp::whole(seconds).is_ok()
        && precise.is_none_or(|at| at.seconds() == seconds && subsecond(at).is_some())
}

pub(super) fn display_duration(seconds: u64, nanos: u32) -> String {
    if nanos == 0 {
        return format!("{seconds}s");
    }
    let fraction = format!("{nanos:09}");
    format!("{seconds}.{}s", fraction.trim_end_matches('0'))
}

// The import accepts exact nonnegative Go-style units. No float is used, and a
// fractional component must resolve to an integer number of nanoseconds.
fn parse_duration(text: &str) -> Result<(u64, u32)> {
    if text == "0" {
        return Ok((0, 0));
    }
    if text.is_empty() || text.len() > 128 {
        return Err(bad("KV2 import duration rejected"));
    }
    let mut rest = text;
    let mut total = 0_u128;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(bad("KV2 import duration rejected"));
        }
        let whole = rest[..digits]
            .parse::<u128>()
            .map_err(|_| bad("KV2 import duration rejected"))?;
        rest = &rest[digits..];
        let (fraction, scale) = if let Some(after) = rest.strip_prefix('.') {
            let length = after.bytes().take_while(u8::is_ascii_digit).count();
            if length == 0 || length > 9 {
                return Err(bad("KV2 import duration rejected"));
            }
            let fraction = after[..length]
                .parse::<u128>()
                .map_err(|_| bad("KV2 import duration rejected"))?;
            rest = &after[length..];
            (fraction, 10_u128.pow(length as u32))
        } else {
            (0, 1)
        };
        let mut unit = None;
        for (label, multiplier) in [
            ("ns", 1_u128),
            ("us", 1_000),
            ("µs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ] {
            if let Some(after) = rest.strip_prefix(label) {
                unit = Some(multiplier);
                rest = after;
                break;
            }
        }
        let multiplier = unit.ok_or_else(|| bad("KV2 import duration rejected"))?;
        let scaled = whole
            .checked_mul(scale)
            .and_then(|v| v.checked_add(fraction))
            .and_then(|v| v.checked_mul(multiplier))
            .ok_or_else(|| bad("KV2 import duration rejected"))?;
        if scaled % scale != 0 {
            return Err(bad("KV2 import duration has subnanosecond precision"));
        }
        total = total
            .checked_add(scaled / scale)
            .ok_or_else(|| bad("KV2 import duration rejected"))?;
        if total > 315_360_000_u128 * u128::from(NANOS) {
            return Err(bad("KV2 import duration exceeds ten years"));
        }
    }
    Ok((
        (total / u128::from(NANOS)) as u64,
        (total % u128::from(NANOS)) as u32,
    ))
}

pub(super) fn deletion_deadline(
    now: Timestamp,
    key: &Config,
    engine: &Config,
) -> Result<Option<Timestamp>> {
    let key = (key.delete_version_after, key.delete_version_after_nanos);
    let engine = (
        engine.delete_version_after,
        engine.delete_version_after_nanos,
    );
    let duration = match (key, engine) {
        ((0, 0), engine) => engine,
        (key, (0, 0)) => key,
        (key, engine) => key.min(engine),
    };
    if duration == (0, 0) {
        return Ok(None);
    }
    let nanos = u64::from(now.duration_since_epoch().subsec_nanos()) + u64::from(duration.1);
    let seconds = now
        .seconds()
        .checked_add(duration.0)
        .and_then(|s| s.checked_add(nanos / NANOS))
        .ok_or_else(|| bad("deletion deadline overflow"))?;
    Timestamp::checked(seconds, (nanos % NANOS) as u32)
        .map(Some)
        .map_err(|_| bad("deletion deadline overflow"))
}

fn parse_time(text: &str) -> Result<Timestamp> {
    let bytes = text.as_bytes();
    if !text.is_ascii()
        || !(20..=30).contains(&bytes.len())
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
    {
        return Err(bad("KV2 import timestamp rejected"));
    }
    let number = |start: usize, end: usize| -> Result<i64> {
        if !bytes[start..end].iter().all(u8::is_ascii_digit) {
            return Err(bad("KV2 import timestamp rejected"));
        }
        text[start..end]
            .parse::<i64>()
            .map_err(|_| bad("KV2 import timestamp rejected"))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad("KV2 import timestamp rejected"));
    }
    let nanos = if bytes.len() == 20 {
        0
    } else {
        if bytes[19] != b'.' || !(22..=30).contains(&bytes.len()) {
            return Err(bad("KV2 import timestamp rejected"));
        }
        let digits = &text[20..text.len() - 1];
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad("KV2 import timestamp rejected"));
        }
        digits
            .parse::<u32>()
            .map_err(|_| bad("KV2 import timestamp rejected"))?
            * 10_u32.pow((9 - digits.len()) as u32)
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year / 400;
    let yoe = adjusted_year - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    let seconds = days
        .checked_mul(86400)
        .and_then(|v| v.checked_add(hour * 3600 + minute * 60 + second))
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| bad("KV2 import timestamp rejected"))?;
    let at =
        Timestamp::checked(seconds, nanos).map_err(|_| bad("KV2 import timestamp rejected"))?;
    // Round-trip also rejects impossible calendar dates and noncanonical zeros.
    if at.rfc3339() != text {
        return Err(bad("KV2 import timestamp rejected"));
    }
    Ok(at)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import<'a> {
    schema: String,
    config: ImportConfig,
    #[serde(borrow)]
    entries: BTreeMap<String, ImportEntry<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportConfig {
    max_versions: u64,
    cas_required: bool,
    metadata_cas_required: bool,
    delete_version_after: String,
}
impl ImportConfig {
    fn into_config(self) -> Result<Config> {
        if self.max_versions > MAX_RETAINED_VERSIONS {
            return Err(bad("KV2 import retention bound exceeded"));
        }
        let (seconds, nanos) = parse_duration(&self.delete_version_after)?;
        Ok(Config {
            max_versions: self.max_versions,
            cas_required: self.cas_required,
            metadata_cas_required: self.metadata_cas_required,
            delete_version_after: seconds,
            delete_version_after_nanos: nanos,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportEntry<'a> {
    created_time: String,
    updated_time: String,
    current_version: u64,
    current_metadata_version: u64,
    oldest_version: u64,
    max_versions: u64,
    cas_required: bool,
    metadata_cas_required: bool,
    delete_version_after: String,
    #[serde(deserialize_with = "required_metadata")]
    custom_metadata: Option<BTreeMap<String, String>>,
    #[serde(borrow)]
    versions: BTreeMap<String, ImportVersion<'a>>,
}
fn required_metadata<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<BTreeMap<String, String>>, D::Error> {
    Option::<BTreeMap<String, String>>::deserialize(decoder)
}

impl Drop for ImportEntry<'_> {
    fn drop(&mut self) {
        if let Some(metadata) = self.custom_metadata.take() {
            for (mut key, mut value) in metadata {
                key.zeroize();
                value.zeroize();
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportVersion<'a> {
    created_time: String,
    deletion_time: String,
    destroyed: bool,
    #[serde(default)]
    source_deletion_time: String,
    #[serde(borrow)]
    data: &'a serde_json::value::RawValue,
}

// The shared token boundary never projects user private-transport objects.
pub(crate) fn decode_lossless_json(bytes: &[u8]) -> Result<Value> {
    heptabao_domain::json::decode(bytes).map_err(|_| bad("bounded secret JSON rejected"))
}
pub(crate) fn deserialize_secret_json<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Value, D::Error> {
    heptabao_domain::json::deserialize(deserializer)
}

pub(super) fn needs_lossless_number_format(value: &Value) -> bool {
    heptabao_domain::json::requires_lossless_format(value)
}

impl Kv2 {
    /// Returns one fully validated, privately owned candidate. This does not
    /// publish, merge, mutate an existing engine, or grant request authority.
    pub(in crate::engines) fn from_lossless_import_json(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_IMPORT_BYTES {
            return Err(bad("KV2 import byte bound exceeded"));
        }
        let validated = SecretJson(decode_lossless_json(bytes)?);
        drop(validated);
        let input: Import<'_> =
            serde_json::from_slice(bytes).map_err(|_| bad("KV2 import closed schema rejected"))?;
        if input.schema != IMPORT_SCHEMA || input.entries.len() > MAX_IMPORT_ENTRIES {
            return Err(bad("KV2 import schema or entry bound rejected"));
        }
        let config = input.config.into_config()?;
        let mut candidate = Self {
            config,
            entries: BTreeMap::new(),
            lossless_format: Some(1),
        };
        let mut total_versions = 0_usize;
        for (name, mut source) in input.entries {
            valid_path(&name)?;
            total_versions = total_versions
                .checked_add(source.versions.len())
                .ok_or_else(|| bad("KV2 import version bound exceeded"))?;
            if total_versions > MAX_IMPORT_VERSIONS
                || source.versions.len() > MAX_RETAINED_VERSIONS as usize
            {
                return Err(bad("KV2 import version bound exceeded"));
            }
            let created = parse_time(&source.created_time)?;
            let updated = parse_time(&source.updated_time)?;
            if updated < created
                || source.current_version > i64::MAX as u64
                || source.oldest_version > source.current_version
            {
                return Err(bad("KV2 import metadata range rejected"));
            }
            let first = source.oldest_version.max(1);
            let expected = if source.current_version == 0 {
                0
            } else {
                source.current_version - first + 1
            };
            if source.versions.len() as u64 != expected
                || (source.current_version == 0 && source.oldest_version != 0)
            {
                return Err(bad("KV2 import retained history is incomplete"));
            }
            let key_config = ImportConfig {
                max_versions: source.max_versions,
                cas_required: source.cas_required,
                metadata_cas_required: source.metadata_cas_required,
                delete_version_after: std::mem::take(&mut source.delete_version_after),
            }
            .into_config()?;
            let mut entry = Entry::new(created.seconds());
            entry.config = key_config;
            entry.updated_at = updated.seconds();
            entry.current_version = source.current_version;
            entry.current_metadata_version = source.current_metadata_version;
            entry.oldest_version = source.oldest_version;
            entry.custom_metadata = source.custom_metadata.take();
            entry.precision.created_at = subsecond(created);
            entry.precision.updated_at = subsecond(updated);
            for (number, imported) in std::mem::take(&mut source.versions) {
                let version_number = number
                    .parse::<u64>()
                    .map_err(|_| bad("KV2 import version key rejected"))?;
                if number != version_number.to_string()
                    || version_number < first
                    || version_number > source.current_version
                {
                    return Err(bad("KV2 import version key rejected"));
                }
                let issued = parse_time(&imported.created_time)?;
                let deleted = if imported.deletion_time.is_empty() {
                    None
                } else {
                    Some(parse_time(&imported.deletion_time)?)
                };
                let source_deletion = if imported.source_deletion_time.is_empty() {
                    None
                } else {
                    Some(parse_time(&imported.source_deletion_time)?)
                };
                let mut imported_data =
                    SecretJson(decode_lossless_json(imported.data.get().as_bytes())?);
                if issued < created
                    || issued > updated
                    || deleted.is_some_and(|at| at < issued)
                    || (imported.destroyed && !imported_data.0.is_null())
                    || (!imported.destroyed && !imported_data.0.is_object())
                    || source_deletion.is_some_and(|at| at < issued)
                {
                    return Err(bad("KV2 import version state rejected"));
                }
                entry.precision.set_version(
                    version_number,
                    VersionPrecision {
                        created_at: subsecond(issued),
                        deletion_at: deleted.and_then(subsecond),
                        source_deletion_at: source_deletion,
                    },
                );
                let data = if imported.destroyed {
                    None
                } else {
                    Some(SharedJson::from(SecretJson(std::mem::take(
                        &mut imported_data.0,
                    ))))
                };
                entry.versions.insert(
                    version_number,
                    Version {
                        created_at: issued.seconds(),
                        deletion_at: deleted.map(Timestamp::seconds),
                        destroyed: imported.destroyed,
                        data,
                    },
                );
            }
            candidate.entries.insert(name, entry);
        }
        candidate.validate_lossless_state()?;
        Ok(candidate)
    }

    pub(in crate::engines) fn is_pristine_for_import(&self) -> bool {
        self.entries.is_empty()
            && self.lossless_format.is_none()
            && self.config.max_versions == 0
            && !self.config.cas_required
            && !self.config.metadata_cas_required
            && self.config.delete_version_after == 0
            && self.config.delete_version_after_nanos == 0
    }

    pub(in crate::engines) fn has_lossless_import_state(&self) -> bool {
        self.lossless_format.is_some()
            || self.config.delete_version_after_nanos != 0
            || self.entries.values().any(|entry| {
                entry.config.delete_version_after_nanos != 0
                    || !entry.precision.is_empty()
                    || entry.versions.values().any(|version| {
                        version
                            .data
                            .as_ref()
                            .is_some_and(|data| needs_lossless_number_format(data.expose()))
                    })
            })
    }

    pub(in crate::engines) fn validate_lossless_state(&self) -> Result<()> {
        let marked = self.has_lossless_import_state();
        if (marked && self.lossless_format != Some(1))
            || self.lossless_format.is_some_and(|format| format != 1)
            || self.config.delete_version_after_nanos >= NANOS as u32
            || self.config.delete_version_after > 315_360_000
            || marked && self.config.max_versions > MAX_RETAINED_VERSIONS
        {
            return Err(bad("KV2 persisted lossless format rejected"));
        }
        for (name, entry) in &self.entries {
            valid_path(name)?;
            if entry.config.delete_version_after_nanos >= NANOS as u32
                || entry.config.delete_version_after > 315_360_000
                || !consistent_time(entry.created_at, entry.precision.created_at)
                || !consistent_time(entry.updated_at, entry.precision.updated_at)
            {
                return Err(bad("KV2 persisted timestamp rejected"));
            }
            if marked {
                let first = entry.oldest_version.max(1);
                if entry.current_version > i64::MAX as u64
                    || entry.oldest_version > entry.current_version
                    || (entry.current_version == 0
                        && (entry.oldest_version != 0 || !entry.versions.is_empty()))
                    || (entry.current_version > 0
                        && entry.versions.len() as u64 != entry.current_version - first + 1)
                    || entry.config.max_versions > MAX_RETAINED_VERSIONS
                    || self.config.max_versions > MAX_RETAINED_VERSIONS
                {
                    return Err(bad("KV2 persisted lossless history rejected"));
                }
                for (number, version) in &entry.versions {
                    if *number < first
                        || *number > entry.current_version
                        || !consistent_time(
                            version.created_at,
                            entry.version_precision(*number).created_at,
                        )
                        || version.deletion_at.is_some_and(|seconds| {
                            !consistent_time(seconds, entry.version_precision(*number).deletion_at)
                        })
                        || (version.destroyed && version.data.is_some())
                        || (!version.destroyed
                            && !version
                                .data
                                .as_ref()
                                .is_some_and(|data| data.expose().is_object()))
                    {
                        return Err(bad("KV2 persisted lossless version rejected"));
                    }
                }
            }
            for (number, precise) in &entry.precision.versions {
                let version = entry
                    .versions
                    .get(number)
                    .ok_or_else(|| bad("KV2 persisted precision has no version"))?;
                if (precise.created_at.is_none()
                    && precise.deletion_at.is_none()
                    && precise.source_deletion_at.is_none())
                    || !consistent_time(version.created_at, precise.created_at)
                    || precise.source_deletion_at.is_some_and(|source| {
                        (
                            source.seconds(),
                            source.duration_since_epoch().subsec_nanos(),
                        ) < (
                            version.created_at,
                            precise
                                .created_at
                                .map_or(0, |at| at.duration_since_epoch().subsec_nanos()),
                        )
                    })
                    || match version.deletion_at {
                        Some(seconds) => !consistent_time(seconds, precise.deletion_at),
                        None => precise.deletion_at.is_some(),
                    }
                {
                    return Err(bad("KV2 persisted version precision rejected"));
                }
            }
        }
        Ok(())
    }
}

impl Kv2 {
    pub(in crate::engines) fn has_lossless_json_state(&self) -> bool {
        self.entries.values().any(|entry| {
            entry.versions.values().any(|version| {
                version.data.as_ref().is_some_and(|data| {
                    heptabao_domain::json::requires_lossless_format(data.expose())
                })
            })
        })
    }
}
