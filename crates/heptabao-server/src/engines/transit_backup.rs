//! Bounded typed OpenBao 2.7 private backup wire format, measured using the compiled vendor.
use super::*;
use chrono::DateTime;
#[path = "transit_backup_crypto.rs"]
mod crypto;

const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_VERSIONS: u64 = 10_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Metadata {
    pub(super) kdf: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hmac_key_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_rotate_period_nanoseconds: Option<i64>,
    archive_min_version: u64,
    min_available_version: u64,
    version_template: String,
    storage_prefix: String,
    backup_info: Option<Stamp>,
    restore_info: Option<Stamp>,
    version_times: BTreeMap<u64, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stamp {
    time: String,
    version: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: Option<String>,
    hmac_key: Option<String>,
    time: String,
    #[serde(default)]
    ec_x: Option<crypto::Decimal>,
    #[serde(default)]
    ec_y: Option<crypto::Decimal>,
    #[serde(default)]
    ec_d: Option<crypto::Decimal>,
    #[serde(default)]
    rsa_key: Option<crypto::RsaPrivate>,
    #[serde(default)]
    rsa_public_key: Value,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    convergent_version: u64,
    creation_time: u64,
    #[serde(default)]
    certificate_chain: Value,
    #[serde(default)]
    external_key_ref: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
        if let Some(key) = &mut self.hmac_key {
            key.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    name: String,
    #[serde(deserialize_with = "unique_versions")]
    keys: BTreeMap<String, Entry>,
    derived: bool,
    kdf: u8,
    convergent_encryption: bool,
    exportable: bool,
    min_decryption_version: u64,
    min_encryption_version: u64,
    latest_version: u64,
    archive_version: u64,
    #[serde(default)]
    archive_min_version: u64,
    #[serde(default)]
    min_available_version: u64,
    deletion_allowed: bool,
    convergent_version: u64,
    #[serde(rename = "type")]
    kind: u8,
    backup_info: Option<Stamp>,
    restore_info: Option<Stamp>,
    #[serde(default)]
    allow_plaintext_backup: bool,
    #[serde(default)]
    version_template: String,
    #[serde(default)]
    storage_prefix: String,
    #[serde(default, deserialize_with = "native_rotation_duration")]
    auto_rotate_period: i64,
    #[serde(default, rename = "Imported")]
    imported: bool,
    #[serde(default, rename = "AllowImportedKeyRotation")]
    allow_imported_rotation: bool,
    #[serde(default)]
    soft_deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_size: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archived {
    keys: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    policy: Policy,
    archived_keys: Archived,
}

fn unique_versions<'de, D>(d: D) -> std::result::Result<BTreeMap<String, Entry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, Entry>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded map of distinct canonical key versions")
        }
        fn visit_map<A>(self, mut a: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut out = BTreeMap::new();
            while let Some((k, v)) = a.next_entry::<String, Entry>()? {
                if out.len() >= MAX_VERSIONS as usize || out.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate or excessive backup versions",
                    ));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(Visitor)
}

fn kind_code(kind: &str) -> Result<u8> {
    match kind {
        "aes256-gcm96" => Ok(0),
        "ecdsa-p256" => Ok(1),
        "ed25519" => Ok(2),
        "rsa-2048" => Ok(3),
        "rsa-4096" => Ok(4),
        "ecdsa-p384" => Ok(6),
        "ecdsa-p521" => Ok(7),
        "rsa-3072" => Ok(9),
        "hmac" => Ok(10),
        "mldsa-44" => Ok(12),
        "mldsa-65" => Ok(13),
        "mldsa-87" => Ok(14),
        "chacha20-poly1305" => Ok(5),
        "aes128-gcm96" => Ok(8),
        "xchacha20-poly1305" => Ok(11),
        _ => Err(error(
            501,
            "plaintext backups for this key type are not implemented",
        )),
    }
}

fn kind_name(code: u8) -> Result<&'static str> {
    match code {
        0 => Ok("aes256-gcm96"),
        1 => Ok("ecdsa-p256"),
        2 => Ok("ed25519"),
        3 => Ok("rsa-2048"),
        4 => Ok("rsa-4096"),
        6 => Ok("ecdsa-p384"),
        7 => Ok("ecdsa-p521"),
        9 => Ok("rsa-3072"),
        10 => Ok("hmac"),
        12 => Ok("mldsa-44"),
        13 => Ok("mldsa-65"),
        14 => Ok("mldsa-87"),
        5 => Ok("chacha20-poly1305"),
        8 => Ok("aes128-gcm96"),
        11 => Ok("xchacha20-poly1305"),
        _ => Err(error(
            501,
            "restoring this backup key type is not implemented",
        )),
    }
}

fn time_seconds(value: &str) -> Result<u64> {
    if value.len() > 40 {
        return Err(bad("invalid backup timestamp"));
    }
    let t = DateTime::parse_from_rfc3339(value).map_err(|_| bad("invalid backup timestamp"))?;
    u64::try_from(t.timestamp()).map_err(|_| bad("invalid backup timestamp"))
}

// Native backups carry Go's signed Duration, independently of public configuration validation.
fn native_rotation_duration<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<i64, D::Error> {
    i64::deserialize(d).map_err(|_| serde::de::Error::custom("invalid native rotation duration"))
}

fn restored_rotation_period(nanoseconds: i64) -> u64 {
    u64::try_from(nanoseconds / 1_000_000_000).unwrap_or(0)
}

pub(super) fn rotation_nanoseconds(key: &Key) -> Result<i64> {
    if let Some(nanos) = key
        .backup_metadata
        .as_ref()
        .and_then(|m| m.auto_rotate_period_nanoseconds)
    {
        return Ok(nanos);
    }
    i64::try_from(key.auto_rotate_period)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .ok_or_else(|| bad("transit rotation duration overflow"))
}

pub(super) fn has_positive_rotation_period(key: &Key) -> bool {
    key.backup_metadata
        .as_ref()
        .and_then(|m| m.auto_rotate_period_nanoseconds)
        .map_or(key.auto_rotate_period != 0, |nanos| nanos > 0)
}

pub(super) fn configure_rotation_period(key: &mut Key, seconds: u64) -> Result<()> {
    let nanoseconds = i64::try_from(seconds)
        .ok()
        .and_then(|v| v.checked_mul(1_000_000_000))
        .ok_or_else(|| bad("transit rotation duration overflow"))?;
    if let Some(m) = &mut key.backup_metadata
        && (m.auto_rotate_period_nanoseconds.is_some()
            || (seconds > 0
                && m.version_times.values().any(|value| {
                    DateTime::parse_from_rfc3339(value)
                        .is_ok_and(|at| at.timestamp_subsec_nanos() != 0)
                })))
    {
        m.auto_rotate_period_nanoseconds = Some(nanoseconds);
    }
    key.auto_rotate_period = seconds;
    Ok(())
}

pub(super) fn creation_nanoseconds(key: &Key, number: u64) -> Result<u128> {
    let version = key
        .versions
        .get(&number)
        .ok_or_else(|| error(500, "transit version missing"))?;
    if let Some(value) = key
        .backup_metadata
        .as_ref()
        .and_then(|m| m.version_times.get(&number))
    {
        let at =
            DateTime::parse_from_rfc3339(value).map_err(|_| bad("invalid backup timestamp"))?;
        let seconds = u64::try_from(at.timestamp()).map_err(|_| bad("invalid backup timestamp"))?;
        if seconds != version.created_at {
            return Err(bad("backup timestamp and creation time disagree"));
        }
        return Ok(u128::from(seconds) * 1_000_000_000 + u128::from(at.timestamp_subsec_nanos()));
    }
    Ok(u128::from(version.created_at) * 1_000_000_000)
}

pub(super) fn record_rotation_creation(
    key: &mut Key,
    number: u64,
    at: crate::auth::Timestamp,
) -> Result<()> {
    let period = rotation_nanoseconds(key)?;
    if key
        .backup_metadata
        .as_ref()
        .is_some_and(|m| m.auto_rotate_period_nanoseconds.is_some())
        || (at.duration_since_epoch().subsec_nanos() != 0
            && is_kind(&key.kind)
            && !byok::imported_key(key)
            && !key.convergent_encryption
            && key.convergent_write_min_version == 0
            && key.versions.values().all(|v| v.public_key_only.is_none()))
    {
        let mut m = metadata(key);
        m.auto_rotate_period_nanoseconds = Some(period);
        m.version_times.insert(number, at.rfc3339());
        key.backup_metadata = Some(m);
    }
    Ok(())
}

pub(super) fn has_rotation_precision(key: &Key) -> bool {
    key.backup_metadata
        .as_ref()
        .is_some_and(|m| m.auto_rotate_period_nanoseconds.is_some())
}

fn stamp_valid(value: &Option<Stamp>, latest: u64) -> Result<()> {
    if let Some(v) = value {
        if v.version == 0 || v.version > latest {
            return Err(bad("invalid backup information version"));
        }
        time_seconds(&v.time)?;
    }
    Ok(())
}

impl Entry {
    fn empty() -> Self {
        Self {
            key: None,
            hmac_key: None,
            time: "0001-01-01T00:00:00Z".into(),
            ec_x: None,
            ec_y: None,
            ec_d: None,
            rsa_key: None,
            rsa_public_key: Value::Null,
            public_key: String::new(),
            convergent_version: 0,
            creation_time: 0,
            certificate_chain: Value::Null,
            external_key_ref: String::new(),
        }
    }
    fn empty_exact(&self) -> bool {
        self == &Self::empty()
    }
    fn version(&self, kind: &str, key_size: Option<u64>, derived: bool) -> Result<KeyVersion> {
        let mut material = crypto::material(self, kind, key_size)?;
        if kind == "ed25519" && derived {
            let raw = self
                .key
                .as_deref()
                .ok_or_else(|| bad("derived signing master missing"))?;
            derivation::validate_ed_master(&stored_material(raw)?)?;
            material.zeroize();
            material = raw.into();
        }
        Ok(KeyVersion {
            material,
            hmac_material: self
                .hmac_key
                .as_deref()
                .ok_or_else(|| bad("backup HMAC missing"))?
                .into(),
            public_key_only: None,
            created_at: self.creation_time,
            encryptions: 0,
            external_key_ref: None,
            heptabao_convergent_version: None,
        })
    }
}

pub(super) fn is_kind(kind: &str) -> bool {
    kind_code(kind).is_ok()
}

pub(super) fn hmac_key_size(key: &Key) -> Option<u64> {
    (key.kind == "hmac").then(|| {
        key.backup_metadata
            .as_ref()
            .and_then(|m| m.hmac_key_size)
            .unwrap_or(32)
    })
}
pub(super) fn hmac_material<'a>(key: &Key, version: &'a KeyVersion) -> &'a str {
    if key.kind == "hmac"
        && key
            .backup_metadata
            .as_ref()
            .is_some_and(|m| m.hmac_key_size.is_some())
    {
        &version.material
    } else {
        &version.hmac_material
    }
}
pub(super) fn native_hmac_metadata(size: u64) -> Metadata {
    Metadata {
        kdf: 0,
        hmac_key_size: Some(size),
        auto_rotate_period_nanoseconds: None,
        archive_min_version: 0,
        min_available_version: 0,
        version_template: String::new(),
        storage_prefix: String::new(),
        backup_info: None,
        restore_info: None,
        version_times: BTreeMap::new(),
    }
}
pub(super) fn generate_version(key: &Key, now: u64) -> Result<KeyVersion> {
    let mut v = if derivation::is_ed(key) {
        derivation::generate_ed_version(now)?
    } else {
        KeyVersion::generate(&key.kind, now)?
    };
    if key.kind == "hmac"
        && key
            .backup_metadata
            .as_ref()
            .is_some_and(|m| m.hmac_key_size.is_some())
    {
        let size = hmac_key_size(key).ok_or_else(|| bad("HMAC key size missing"))?;
        if !(32..=512).contains(&size) {
            return Err(bad("invalid HMAC key size"));
        }
        v.material = BASE64.encode(random_bytes(size as usize)?.as_slice());
    }
    Ok(v)
}

pub(super) fn min_available_version(key: &Key) -> u64 {
    key.backup_metadata
        .as_ref()
        .map_or(0, |m| m.min_available_version)
}

pub(super) fn decorate_descriptor(key: &Key, descriptor: &mut Value) {
    if let Some(nanoseconds) = key
        .backup_metadata
        .as_ref()
        .and_then(|m| m.auto_rotate_period_nanoseconds)
    {
        descriptor["auto_rotate_period"] = json!(nanoseconds / 1_000_000_000);
    }
    if key.kind == "hmac"
        && key
            .backup_metadata
            .as_ref()
            .is_some_and(|m| m.hmac_key_size.is_some())
        && let Some(fields) = descriptor.as_object_mut()
    {
        fields.remove("keys");
        fields.remove("supports_hmac");
        fields.insert("key_size".into(), json!(hmac_key_size(key)));
    }
    if let Some(m) = &key.backup_metadata {
        for (name, stamp) in [
            ("backup_info", &m.backup_info),
            ("restore_info", &m.restore_info),
        ] {
            if let Some(stamp) = stamp {
                descriptor[name] = json!({"time":stamp.time,"version":stamp.version});
            }
        }
    }
}

fn metadata(key: &Key) -> Metadata {
    key.backup_metadata.clone().unwrap_or_else(|| Metadata {
        kdf: u8::from(
            (symmetric::is_kind(&key.kind) && !key.legacy_counter_kdf && key.byok.is_none())
                || derivation::is_ed(key),
        ),
        hmac_key_size: None,
        auto_rotate_period_nanoseconds: None,
        archive_min_version: 0,
        min_available_version: 0,
        version_template: String::new(),
        storage_prefix: String::new(),
        backup_info: None,
        restore_info: None,
        version_times: BTreeMap::new(),
    })
}

pub(super) fn trim(key: &mut Key, body: &Value) -> Result<()> {
    reject_unknown(body, &["min_available_version"])?;
    key.alive()?;
    kind_code(&key.kind)?;
    if key.convergent_encryption || key.convergent_write_min_version != 0 {
        return Err(bad(
            "trimming protected convergent key material is not supported",
        ));
    }
    let requested = optional_u64(body, "min_available_version")?
        .ok_or_else(|| bad("min_available_version is required"))?;
    let current = min_available_version(key);
    if key.min_encryption_version == 0 {
        return Err(bad(
            "minimum available version cannot be set when minimum encryption version is not set",
        ));
    }
    if requested < current {
        return Err(bad("minimum available version cannot be decremented"));
    }
    if requested == 0 {
        return Err(bad("minimum available version must be positive"));
    }
    if requested > key.min_encryption_version {
        return Err(bad(
            "minimum available version cannot be greater than minmum encryption version",
        ));
    }
    if requested > key.min_decryption_version {
        return Err(bad(
            "minimum available version cannot be greater than minimum decryption version",
        ));
    }
    // Validate a complete replacement before discarding any historical secret.
    let mut prepared = key.clone();
    let mut m = metadata(key);
    m.archive_min_version = requested;
    m.min_available_version = requested;
    m.version_times.retain(|n, _| *n >= requested);
    prepared.versions.retain(|n, _| *n >= requested);
    prepared.backup_metadata = Some(m);
    validate_key(&prepared)?;
    *key = prepared;
    Ok(())
}

pub(super) fn validate_key(key: &Key) -> Result<()> {
    if key.allow_plaintext_backup
        && (!is_kind(&key.kind)
            || key.convergent_encryption
            || key.convergent_write_min_version != 0)
    {
        return Err(bad(
            "plaintext backup cannot expose protected or unsupported key material",
        ));
    }
    if key.legacy_counter_kdf
        && (!key.derived
            || !symmetric::is_kind(&key.kind)
            || key.convergent_encryption
            || (key.byok.is_none() && key.backup_metadata.is_none()))
    {
        return Err(bad("invalid legacy imported derivation policy"));
    }
    if let Some(m) = &key.backup_metadata {
        kind_code(&key.kind)?;
        if m.kdf > 1
            || m.archive_min_version > m.min_available_version
            || m.min_available_version > key.min_decryption_version
            || key.legacy_counter_kdf != (key.derived && m.kdf == 0)
            || (!symmetric::is_kind(&key.kind)
                && !derivation::is_ed(key)
                && (key.derived || m.kdf != 0))
            || (derivation::is_ed(key) && (m.kdf != 1 || key.byok.is_some()))
            || m.hmac_key_size
                .is_some_and(|n| key.kind != "hmac" || !(32..=512).contains(&n))
            || !m.version_template.is_empty()
            || m.storage_prefix.len() > 256
            || m.version_times.len() > MAX_VERSIONS as usize
        {
            return Err(bad("invalid symmetric backup metadata"));
        }
        if m.auto_rotate_period_nanoseconds
            .is_some_and(|nanos| restored_rotation_period(nanos) != key.auto_rotate_period)
        {
            return Err(bad("rotation duration and legacy projection disagree"));
        }
        stamp_valid(&m.backup_info, key.latest_version)?;
        stamp_valid(&m.restore_info, key.latest_version)?;
        for (n, t) in &m.version_times {
            let seconds = time_seconds(t)?;
            if *n == 0 || *n > key.latest_version {
                return Err(bad("invalid backup version timestamp"));
            }
            if let Some(v) = key.versions.get(n)
                && seconds != v.created_at
            {
                return Err(bad("backup timestamp and creation time disagree"));
            }
        }
        if key.versions.is_empty() || key.versions.keys().next_back() != Some(&key.latest_version) {
            return Err(bad("invalid restored key version range"));
        }
    }
    if key.allow_plaintext_backup || key.backup_metadata.is_some() {
        for (n, v) in &key.versions {
            if *n == 0 || *n < min_available_version(key).max(1) {
                return Err(bad("invalid restored key version"));
            }
            crypto::validate_version(key, v)?;
        }
    }
    Ok(())
}

impl Transit {
    pub(in crate::engines) fn has_symmetric_backup_state(&self) -> bool {
        self.keys.values().any(|key| {
            key.allow_plaintext_backup
                || key.legacy_counter_kdf
                || key.backup_metadata.is_some()
                || (key.byok.is_some()
                    && matches!(
                        key.kind.as_str(),
                        "chacha20-poly1305" | "xchacha20-poly1305"
                    ))
        })
    }

    pub(super) fn backup(
        &mut self,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if method != "GET" {
            return Err(unsupported());
        }
        reject_unknown(body, &[])?;
        valid_path(name)?;
        let key = self.keys.get(name).ok_or_else(not_found)?;
        key.alive()?;
        if !key.allow_plaintext_backup {
            return Err(bad("plaintext backup is not allowed for this key"));
        }
        validate_key(key)?;
        kind_code(&key.kind)?;
        if key.versions.is_empty() || key.latest_version > MAX_VERSIONS {
            return Err(bad("backup key version range exceeds supported bounds"));
        }
        let mut m = metadata(key);
        m.backup_info = Some(Stamp {
            time: timestamp(now),
            version: key.latest_version,
        });
        let mut entries = BTreeMap::new();
        for (n, v) in &key.versions {
            let t = m
                .version_times
                .get(n)
                .cloned()
                .unwrap_or_else(|| timestamp(v.created_at));
            entries.insert(n.to_string(), crypto::from_version(key, v, t)?);
        }
        let mut archived = Vec::new();
        for n in m.archive_min_version..=key.latest_version {
            if n == 0 {
                archived.push(Entry::empty());
            } else {
                let e = entries
                    .get(&n.to_string())
                    .ok_or_else(|| bad("backup contains unavailable historical versions"))?;
                archived.push(e.clone());
            }
        }
        let wire = Backup {
            policy: Policy {
                name: name.into(),
                keys: entries
                    .into_iter()
                    .filter(|(n, _)| {
                        n.parse::<u64>()
                            .is_ok_and(|n| n >= key.min_decryption_version)
                    })
                    .collect(),
                derived: key.derived,
                kdf: m.kdf,
                convergent_encryption: key.convergent_encryption,
                exportable: key.exportable,
                min_decryption_version: key.min_decryption_version,
                min_encryption_version: key.min_encryption_version,
                latest_version: key.latest_version,
                archive_version: key.latest_version,
                archive_min_version: m.archive_min_version,
                min_available_version: m.min_available_version,
                deletion_allowed: key.deletion_allowed,
                convergent_version: 0,
                kind: kind_code(&key.kind)?,
                backup_info: m.backup_info.clone(),
                restore_info: m.restore_info.clone(),
                allow_plaintext_backup: key.allow_plaintext_backup,
                version_template: m.version_template.clone(),
                storage_prefix: m.storage_prefix.clone(),
                auto_rotate_period: rotation_nanoseconds(key)?,
                imported: byok::imported_key(key),
                allow_imported_rotation: byok::rotation_permission(key),
                soft_deleted: key.deleted,
                key_size: hmac_key_size(key),
            },
            archived_keys: Archived { keys: archived },
        };
        let raw = Zeroizing::new(
            serde_json::to_vec(&wire).map_err(|_| error(500, "backup encoding failed"))?,
        );
        if raw.len() > MAX_BACKUP_BYTES {
            return Err(error(413, "backup exceeds supported size"));
        }
        let encoded = BASE64.encode(raw.as_slice());
        self.keys
            .get_mut(name)
            .ok_or_else(not_found)?
            .backup_metadata = Some(m);
        Ok(ok(json!({"backup":encoded}), true))
    }

    pub(super) fn restore(
        &mut self,
        method: &str,
        name: &str,
        body: &Value,
        now: u64,
    ) -> Result<EngineResponse> {
        if !write_method(method) {
            return Err(unsupported());
        }
        reject_unknown(body, &["backup", "force", "name"])?;
        let encoded = string(body, "backup")?;
        if encoded.len() > MAX_BACKUP_BYTES * 4 / 3 + 4 {
            return Err(error(413, "backup exceeds supported size"));
        }
        let raw = BASE64
            .decode(encoded)
            .map(Zeroizing::new)
            .map_err(|_| bad("invalid backup base64"))?;
        if raw.len() > MAX_BACKUP_BYTES {
            return Err(error(413, "backup exceeds supported size"));
        }
        let wire: Backup = serde_json::from_slice(&raw).map_err(|reason| {
            if reason
                .to_string()
                .contains("invalid native rotation duration")
            {
                openbao_compatibility_error("invalid native rotation duration")
            } else {
                bad("invalid or ambiguous backup JSON")
            }
        })?;
        let p = &wire.policy;
        valid_path(&p.name)?;
        if p.name.is_empty() || p.name.contains('/') {
            return Err(bad("invalid backup key name"));
        }
        let provided = body
            .get("name")
            .map(|v| v.as_str().ok_or_else(|| bad("name must be a string")))
            .transpose()?;
        if !name.is_empty() && provided.is_some_and(|v| v != name) {
            return Err(bad("conflicting restore key names"));
        }
        let name = if !name.is_empty() {
            name
        } else {
            provided.unwrap_or(&p.name)
        };
        valid_path(name)?;
        if name.is_empty() || name.contains('/') {
            return Err(bad("invalid restore key name"));
        }
        let force = optional_bool(body, "force")?.unwrap_or(false);
        if self.keys.contains_key(name) && !force {
            return Err(openbao_compatibility_error(&format!(
                "key \"{name}\" already exists"
            )));
        }
        let kind = kind_name(p.kind)?;
        let auto_rotate_period = restored_rotation_period(p.auto_rotate_period);
        if p.latest_version == 0
            || p.latest_version > MAX_VERSIONS
            || p.archive_version != p.latest_version
            || p.kdf > 1
            || (!symmetric::is_kind(kind)
                && !(kind == "ed25519" && p.derived && p.kdf == 1 && !p.imported)
                && (p.derived || p.kdf != 0))
            || if kind == "hmac" {
                p.key_size.is_none_or(|n| !(32..=512).contains(&n))
            } else {
                p.key_size.is_some()
            }
            || p.archive_min_version > p.min_available_version
            || p.min_available_version > p.min_decryption_version
            || p.min_decryption_version == 0
            || p.min_decryption_version > p.latest_version
            || p.min_encryption_version > p.latest_version
            || (p.min_encryption_version != 0
                && p.min_encryption_version < p.min_decryption_version)
            || p.convergent_encryption
            || p.convergent_version != 0
            || !p.version_template.is_empty()
            || p.storage_prefix.len() > 256
            || (p.imported && !p.allow_imported_rotation && p.auto_rotate_period > 0)
            || wire.archived_keys.keys.len() as u64 != p.latest_version - p.archive_min_version + 1
        {
            return Err(bad("invalid or unsupported symmetric backup policy"));
        }
        let mut entries = BTreeMap::new();
        for (i, e) in wire.archived_keys.keys.iter().enumerate() {
            let n = p.archive_min_version + i as u64;
            if n == 0 {
                if !e.empty_exact() {
                    return Err(bad("invalid archive zero entry"));
                }
            } else {
                entries.insert(n, e);
            }
        }
        for (s, e) in &p.keys {
            let n: u64 = s
                .parse()
                .map_err(|_| bad("invalid backup version number"))?;
            if n == 0
                || n.to_string() != *s
                || n > p.latest_version
                || entries.get(&n).is_some_and(|archive| *archive != e)
            {
                return Err(bad("inconsistent backup key and archive versions"));
            }
            entries.insert(n, e);
        }
        if !entries.contains_key(&p.latest_version)
            || entries.len() > MAX_VERSIONS as usize
            || entries.keys().any(|n| *n < p.min_available_version.max(1))
        {
            return Err(bad("invalid available backup versions"));
        }
        let mut versions = BTreeMap::new();
        let mut times = BTreeMap::new();
        for (n, e) in entries {
            versions.insert(n, e.version(kind, p.key_size, p.derived)?);
            times.insert(n, e.time.clone());
        }
        let metadata = Metadata {
            kdf: p.kdf,
            hmac_key_size: p.key_size,
            auto_rotate_period_nanoseconds: (p.auto_rotate_period < 0
                || p.auto_rotate_period % 1_000_000_000 != 0
                || self.keys.get(name).is_some_and(has_rotation_precision)
                || (p.auto_rotate_period > 0
                    && times.values().any(|value| {
                        DateTime::parse_from_rfc3339(value)
                            .is_ok_and(|at| at.timestamp_subsec_nanos() != 0)
                    })))
            .then_some(p.auto_rotate_period),
            archive_min_version: p.archive_min_version,
            min_available_version: p.min_available_version,
            version_template: p.version_template.clone(),
            storage_prefix: p.storage_prefix.clone(),
            backup_info: p.backup_info.clone(),
            restore_info: Some(Stamp {
                time: timestamp(now),
                version: p.latest_version,
            }),
            version_times: times,
        };
        let restored = Key {
            kind: kind.into(),
            byok: byok::restored_policy(p.imported, p.allow_imported_rotation),
            derived: p.derived,
            legacy_counter_kdf: p.derived && p.kdf == 0,
            allow_plaintext_backup: p.allow_plaintext_backup,
            backup_metadata: Some(metadata),
            convergent_encryption: false,
            convergent_write_min_version: 0,
            latest_version: p.latest_version,
            min_decryption_version: p.min_decryption_version,
            min_encryption_version: p.min_encryption_version,
            deletion_allowed: p.deletion_allowed,
            exportable: p.exportable,
            auto_rotate_period,
            deleted: p.soft_deleted,
            versions,
        };
        validate_key(&restored)?;
        if let Some(old) = self.keys.get(name) {
            if old.convergent_write_min_version != 0 || old.convergent_encryption {
                return Err(bad(
                    "restore cannot replace protected convergent key material",
                ));
            }
            if old.allow_plaintext_backup && !restored.allow_plaintext_backup {
                return Err(bad("restore cannot revoke plaintext backup permission"));
            }
        }
        // Prepare the wrapping owner locally; no mutation until every wire/key validation passed.
        let wrapping = if restored.byok.is_some() && self.wrapping_key.is_none() {
            Some(byok::WrappingKey::new()?)
        } else {
            None
        };
        let mut prepared = self.clone();
        if let Some(w) = wrapping {
            prepared.wrapping_key = Some(w);
        }
        if derivation::is_ed(&restored) {
            prepared.derived_ed_format = Some(derivation::Format::V1);
        }
        prepared.keys.insert(name.into(), restored);
        prepared.validate_byok_state()?;
        prepared.validate_derived_ed_state(Some(self))?;
        *self = prepared;
        Ok(empty(true))
    }
}

#[cfg(test)]
#[path = "transit_backup_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "transit_backup_native_tests.rs"]
mod native_tests;
