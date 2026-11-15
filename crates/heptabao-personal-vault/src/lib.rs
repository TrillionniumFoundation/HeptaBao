#![forbid(unsafe_code)]
//! Experimental Unix client-side encrypted personal vault. No production adoption claim.
//! Credentials enter this library locally; encrypted envelopes are the only sync object.

mod crypto;
mod filesystem;
mod otp;

use crypto::Envelope;
pub use filesystem::{read_private_file, write_private_file};
use heptabao_filesystem_guard::ExclusiveDirectory;
pub use otp::{TotpAlgorithm, TotpConfig, generate_password, totp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ITEMS: usize = 4096;
pub const MAX_FIELD_BYTES: usize = 65536;
pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    InvalidInput,
    InvalidFormat,
    WrongKeyOrCorrupt,
    UnsafePath,
    Busy,
    Exists,
    Missing,
    Conflict,
    Locked,
    TooLarge,
    RandomUnavailable,
    Io,
    OutcomeUnknown,
    UnsupportedPlatform,
}
impl VaultError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::InvalidFormat => "invalid_format",
            Self::WrongKeyOrCorrupt => "wrong_key_or_corrupt",
            Self::UnsafePath => "unsafe_path",
            Self::Busy => "vault_busy",
            Self::Exists => "already_exists",
            Self::Missing => "not_found",
            Self::Conflict => "revision_conflict",
            Self::Locked => "locked_or_expired",
            Self::TooLarge => "input_too_large",
            Self::RandomUnavailable => "random_unavailable",
            Self::Io => "io_failure",
            Self::OutcomeUnknown => "save_outcome_unknown",
            Self::UnsupportedPlatform => "unsupported_platform",
        }
    }
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for VaultError {}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Login,
    Note,
    Api,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultItem {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub username: Option<String>,
    pub origin: Option<String>,
    pub secret: String,
    pub notes: String,
    pub totp: Option<TotpConfig>,
}
impl fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultItem")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
impl Drop for VaultItem {
    fn drop(&mut self) {
        self.id.zeroize();
        self.title.zeroize();
        self.username.zeroize();
        self.origin.zeroize();
        self.secret.zeroize();
        self.notes.zeroize();
    }
}
impl VaultItem {
    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || self.title.is_empty()
            || self.title.len() > 1024
            || self.username.as_ref().is_some_and(|x| x.len() > 4096)
            || self.secret.len() > MAX_FIELD_BYTES
            || self.notes.len() > MAX_FIELD_BYTES
        {
            return Err(VaultError::InvalidInput);
        }
        if self.kind == ItemKind::Login {
            let origin = self.origin.as_deref().ok_or(VaultError::InvalidInput)?;
            if !valid_https_origin(origin) || self.secret.is_empty() {
                return Err(VaultError::InvalidInput);
            }
        } else if self
            .origin
            .as_deref()
            .is_some_and(|x| !valid_https_origin(x))
        {
            return Err(VaultError::InvalidInput);
        }
        if let Some(config) = &self.totp {
            config.validate()?;
        }
        Ok(())
    }
}

/// Strict canonical HTTPS origin. International domains must arrive as lowercase ASCII
/// punycode; explicit 443, trailing dots, userinfo, paths, query/fragment and IP literals
/// are refused in this first release to avoid multiple representations of one origin.
pub fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty() || authority.len() > 260 || !authority.is_ascii() {
        return false;
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => {
            if p.is_empty() || p.starts_with('0') || !p.bytes().all(|x| x.is_ascii_digit()) {
                return false;
            }
            let Ok(n) = p.parse::<u16>() else {
                return false;
            };
            if n == 0 || n == 443 {
                return false;
            }
            (h, Some(n))
        }
        None => (authority, None),
    };
    let _ = port;
    if host.len() > 253 || !host.contains('.') || host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // Browser URL parsers also interpret abbreviated, octal and hexadecimal
    // numeric hosts as IPv4. Refuse the numeric last label that selects this
    // parsing branch, rather than accepting a second spelling of an origin.
    let last = host.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|x| x.is_ascii_lowercase() || x.is_ascii_digit() || x == b'-')
    })
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-')
}

#[derive(Debug, Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub origin: Option<String>,
    pub has_totp: bool,
}
#[derive(Debug, Serialize)]
pub struct VaultMetadata {
    pub vault_id: String,
    pub revision: u64,
    pub item_count: usize,
    pub format: u32,
}
#[derive(Debug, Serialize)]
pub struct PasswordHealth {
    pub checked: usize,
    pub empty: usize,
    pub shorter_than_16: usize,
    pub reused_entries: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    vault_id: String,
    revision: u64,
    items: Vec<VaultItem>,
}
impl Payload {
    fn validate(&self) -> Result<()> {
        if self.items.len() > MAX_ITEMS {
            return Err(VaultError::TooLarge);
        }
        let mut ids = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !ids.insert(&item.id) {
                return Err(VaultError::InvalidFormat);
            }
        }
        Ok(())
    }
}

pub struct VaultSession {
    directory: ExclusiveDirectory,
    envelope: Envelope,
    expected_digest: [u8; 32],
    key: Option<Zeroizing<[u8; 32]>>,
    payload: Option<Payload>,
    deadline: Instant,
}
impl fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSession")
            .field("unlocked", &(!self.is_expired()))
            .finish_non_exhaustive()
    }
}
impl VaultSession {
    pub fn create(
        root: &Path,
        password: &[u8],
        ttl: Duration,
    ) -> Result<(Self, Zeroizing<[u8; 32]>)> {
        let (mut session, recovery) = Self::prepare_new(root, password, ttl)?;
        session.write(true)?;
        Ok((session, recovery))
    }
    /// Publish recovery material before creating the first committed envelope.
    /// The recovery output must be in a separate private directory because the
    /// session already owns the vault directory's exclusive writer lock.
    /// A later vault publication failure may leave an unused recovery document;
    /// the caller must inspect state rather than replaying initialization.
    pub fn create_with_recovery_file(
        root: &Path,
        password: &[u8],
        ttl: Duration,
        recovery_output: &Path,
    ) -> Result<Self> {
        #[derive(Serialize)]
        struct RecoveryDocument<'a> {
            format: &'static str,
            vault_id: &'a str,
            recovery_key: &'a str,
        }
        let (mut session, recovery) = Self::prepare_new(root, password, ttl)?;
        let encoded = Zeroizing::new(crypto::encode(recovery.as_slice()));
        let document = RecoveryDocument {
            format: "heptabao-personal-recovery-v1",
            vault_id: &session.envelope.vault_id,
            recovery_key: &encoded,
        };
        let bytes =
            Zeroizing::new(serde_json::to_vec(&document).map_err(|_| VaultError::InvalidFormat)?);
        filesystem::write_private_file(recovery_output, &bytes)?;
        session.write(true)?;
        Ok(session)
    }
    fn prepare_new(
        root: &Path,
        password: &[u8],
        ttl: Duration,
    ) -> Result<(Self, Zeroizing<[u8; 32]>)> {
        let deadline = deadline(ttl)?;
        crypto::validate_password(password)?;
        let directory = filesystem::open_directory(root)?;
        if directory
            .entry_exists("vault.hbv")
            .map_err(|_| VaultError::Io)?
        {
            return Err(VaultError::Exists);
        }
        let (envelope, key, recovery) = Envelope::new(password)?;
        let payload = Payload {
            vault_id: envelope.vault_id.clone(),
            revision: 0,
            items: Vec::new(),
        };
        let session = Self {
            directory,
            envelope,
            expected_digest: [0; 32],
            key: Some(key),
            payload: Some(payload),
            deadline,
        };
        Ok((session, recovery))
    }
    pub fn open(root: &Path, password: &[u8], ttl: Duration) -> Result<Self> {
        let deadline = deadline(ttl)?;
        let directory = filesystem::open_directory(root)?;
        let bytes = filesystem::read_vault(&directory)?;
        let envelope = Envelope::parse(&bytes)?;
        let key = envelope.unlock_password(password)?;
        Self::from_open(directory, envelope, key, &bytes, deadline)
    }
    pub fn unlock(root: &Path, password: &[u8], ttl: Duration) -> Result<Self> {
        Self::open(root, password, ttl)
    }
    pub fn open_with_recovery(root: &Path, recovery: &[u8; 32], ttl: Duration) -> Result<Self> {
        let deadline = deadline(ttl)?;
        let directory = filesystem::open_directory(root)?;
        let bytes = filesystem::read_vault(&directory)?;
        let envelope = Envelope::parse(&bytes)?;
        let key = envelope.unlock_recovery(recovery)?;
        Self::from_open(directory, envelope, key, &bytes, deadline)
    }
    fn from_open(
        directory: ExclusiveDirectory,
        envelope: Envelope,
        key: Zeroizing<[u8; 32]>,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<Self> {
        let plaintext = envelope.decrypt(&key)?;
        let payload: Payload =
            serde_json::from_slice(&plaintext).map_err(|_| VaultError::InvalidFormat)?;
        payload.validate()?;
        if payload.vault_id != envelope.vault_id || payload.revision != envelope.revision {
            return Err(VaultError::WrongKeyOrCorrupt);
        }
        Ok(Self {
            directory,
            envelope,
            expected_digest: crypto::digest(bytes),
            key: Some(key),
            payload: Some(payload),
            deadline,
        })
    }
    pub fn is_expired(&self) -> bool {
        self.key.is_none() || Instant::now() >= self.deadline
    }
    pub fn lock(&mut self) {
        self.key = None;
        self.payload = None;
    }
    fn check(&self) -> Result<&Payload> {
        if self.is_expired() {
            return Err(VaultError::Locked);
        }
        self.payload.as_ref().ok_or(VaultError::Locked)
    }
    fn check_mut(&mut self, expected_revision: u64) -> Result<&mut Payload> {
        if self.is_expired() {
            self.lock();
            return Err(VaultError::Locked);
        }
        if self.envelope.revision != expected_revision {
            return Err(VaultError::Conflict);
        }
        let current = filesystem::read_vault(&self.directory)?;
        if crypto::digest(&current) != self.expected_digest {
            return Err(VaultError::Conflict);
        }
        self.payload.as_mut().ok_or(VaultError::Locked)
    }
    pub fn metadata(&self) -> Result<VaultMetadata> {
        let p = self.check()?;
        Ok(VaultMetadata {
            vault_id: p.vault_id.clone(),
            revision: p.revision,
            item_count: p.items.len(),
            format: 1,
        })
    }
    pub fn summaries(&self) -> Result<Vec<ItemSummary>> {
        Ok(self
            .check()?
            .items
            .iter()
            .map(|x| ItemSummary {
                id: x.id.clone(),
                kind: x.kind,
                title: x.title.clone(),
                origin: x.origin.clone(),
                has_totp: x.totp.is_some(),
            })
            .collect())
    }
    pub fn get(&self, id: &str) -> Result<&VaultItem> {
        self.check()?
            .items
            .iter()
            .find(|x| x.id == id)
            .ok_or(VaultError::Missing)
    }
    /// Exact origin matching only; returning plaintext is an explicit local caller action.
    pub fn login_for_origin(&self, id: &str, exact_https_origin: &str) -> Result<&VaultItem> {
        if !valid_https_origin(exact_https_origin) {
            return Err(VaultError::InvalidInput);
        }
        let item = self.get(id)?;
        if item.kind != ItemKind::Login || item.origin.as_deref() != Some(exact_https_origin) {
            return Err(VaultError::InvalidInput);
        }
        Ok(item)
    }
    pub fn put(&mut self, item: VaultItem, expected_revision: u64) -> Result<()> {
        item.validate()?;
        let p = self.check_mut(expected_revision)?;
        if let Some(existing) = p.items.iter_mut().find(|x| x.id == item.id) {
            *existing = item;
        } else {
            if p.items.len() >= MAX_ITEMS {
                return Err(VaultError::TooLarge);
            }
            p.items.push(item);
        }
        self.advance_and_write()
    }
    pub fn delete(&mut self, id: &str, expected_revision: u64) -> Result<()> {
        let p = self.check_mut(expected_revision)?;
        let index = p
            .items
            .iter()
            .position(|x| x.id == id)
            .ok_or(VaultError::Missing)?;
        p.items.remove(index);
        self.advance_and_write()
    }
    pub fn change_password(&mut self, new_password: &[u8], expected_revision: u64) -> Result<()> {
        crypto::validate_password(new_password)?;
        self.check_mut(expected_revision)?;
        self.envelope
            .rewrap_password(new_password, self.key.as_ref().ok_or(VaultError::Locked)?)?;
        self.advance_and_write()
    }
    fn advance_and_write(&mut self) -> Result<()> {
        self.envelope.revision = self
            .envelope
            .revision
            .checked_add(1)
            .ok_or(VaultError::TooLarge)?;
        self.payload.as_mut().ok_or(VaultError::Locked)?.revision = self.envelope.revision;
        match self.write(false) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.lock();
                Err(e)
            }
        }
    }
    fn write(&mut self, create: bool) -> Result<()> {
        let p = self.check()?;
        let plaintext =
            Zeroizing::new(serde_json::to_vec(p).map_err(|_| VaultError::InvalidFormat)?);
        if plaintext.len() > MAX_FILE_BYTES / 2 {
            return Err(VaultError::TooLarge);
        }
        self.envelope
            .encrypt(self.key.as_ref().ok_or(VaultError::Locked)?, &plaintext)?;
        let bytes = serde_json::to_vec(&self.envelope).map_err(|_| VaultError::InvalidFormat)?;
        filesystem::publish_vault(
            &self.directory,
            &bytes,
            if create {
                None
            } else {
                Some(self.expected_digest)
            },
        )?;
        self.expected_digest = crypto::digest(&bytes);
        Ok(())
    }
    pub fn encrypted_backup(&self) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = filesystem::read_vault(&self.directory)?;
        if crypto::digest(&bytes) != self.expected_digest {
            return Err(VaultError::Conflict);
        }
        Ok(bytes)
    }
    pub fn restore(root: &Path, bytes: &[u8], password: &[u8], ttl: Duration) -> Result<Self> {
        let envelope = Envelope::parse(bytes)?;
        let key = envelope.unlock_password(password)?;
        Self::restore_key(root, bytes, envelope, key, ttl)
    }
    pub fn restore_with_recovery(
        root: &Path,
        bytes: &[u8],
        recovery: &[u8; 32],
        ttl: Duration,
    ) -> Result<Self> {
        let envelope = Envelope::parse(bytes)?;
        let key = envelope.unlock_recovery(recovery)?;
        Self::restore_key(root, bytes, envelope, key, ttl)
    }
    fn restore_key(
        root: &Path,
        bytes: &[u8],
        envelope: Envelope,
        key: Zeroizing<[u8; 32]>,
        ttl: Duration,
    ) -> Result<Self> {
        let directory = filesystem::open_directory(root)?;
        if directory
            .entry_exists("vault.hbv")
            .map_err(|_| VaultError::Io)?
        {
            return Err(VaultError::Exists);
        }
        let session = Self::from_open(directory, envelope, key, bytes, deadline(ttl)?)?;
        filesystem::publish_vault(&session.directory, bytes, None)?;
        Ok(session)
    }
    pub fn export_plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            serde_json::to_vec(self.check()?).map_err(|_| VaultError::InvalidFormat)?,
        ))
    }
    /// Import only same-vault exports, at the caller's currently observed revision.
    pub fn import_plaintext(&mut self, bytes: &[u8], expected_revision: u64) -> Result<()> {
        if bytes.len() > MAX_FILE_BYTES / 2 {
            return Err(VaultError::TooLarge);
        }
        let imported: Payload =
            serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
        imported.validate()?;
        if imported.vault_id != self.envelope.vault_id {
            return Err(VaultError::InvalidInput);
        }
        let p = self.check_mut(expected_revision)?;
        p.items = imported.items;
        self.advance_and_write()
    }
    pub fn health(&self) -> Result<PasswordHealth> {
        let p = self.check()?;
        let mut report = PasswordHealth {
            checked: 0,
            empty: 0,
            shorter_than_16: 0,
            reused_entries: 0,
        };
        for (i, item) in p
            .items
            .iter()
            .enumerate()
            .filter(|(_, x)| x.kind != ItemKind::Note)
        {
            report.checked += 1;
            report.empty += usize::from(item.secret.is_empty());
            report.shorter_than_16 += usize::from(item.secret.chars().count() < 16);
            if p.items.iter().enumerate().any(|(j, other)| {
                j != i && other.kind != ItemKind::Note && other.secret == item.secret
            }) {
                report.reused_entries += 1;
            }
        }
        Ok(report)
    }
}
impl Drop for VaultSession {
    fn drop(&mut self) {
        self.lock();
    }
}
fn deadline(ttl: Duration) -> Result<Instant> {
    if ttl.is_zero() || ttl > Duration::from_secs(3600) {
        return Err(VaultError::InvalidInput);
    }
    Instant::now()
        .checked_add(ttl)
        .ok_or(VaultError::InvalidInput)
}
