//! Crypto preparation only: this module is deliberately not wired into Service.
//! No ring or bootstrap capsule becomes a live storage owner here. A real
//! pre-open backend tuple and post-commit admission are prerequisites.
use crate::crypto;
use ring::{aead, hmac};
use std::collections::BTreeMap;
use std::time::Duration;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const DATA_MAGIC: &[u8; 4] = b"HBA2";
const CAPSULE_MAGIC: &[u8; 4] = b"HBRC";
const CAPSULE_VERSION: u8 = 1;
const PAYLOAD_VERSION: u16 = 1;
const DATA_OVERHEAD: usize = 36;
const CAPSULE_HEADER_BYTES: usize = 13;
const MAX_KEYS: usize = 1024;
const MAX_CAPSULE_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;
pub(crate) const MIN_OPERATIONS: u64 = 1_000_000;
pub(crate) const MAX_OPERATIONS: u64 = 3_865_470_566;
pub(crate) const MIN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    InvalidBinding,
    InvalidConfig,
    InvalidFormat,
    UnsupportedVersion,
    UnknownTerm,
    DuplicateTerm,
    DuplicateMaterial,
    InvalidTerm,
    Authentication,
    Capacity,
    Overflow,
    Randomness,
    ClockRegression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeBinding {
    cluster: String,
    namespace: String,
    custody_identity: [u8; 32],
}
impl ScopeBinding {
    pub(crate) fn root(cluster: String, custody_identity: [u8; 32]) -> Result<Self, Error> {
        if cluster.is_empty()
            || cluster.len() > 256
            || cluster.chars().any(char::is_control)
            || custody_identity == [0; 32]
        {
            return Err(Error::InvalidBinding);
        }
        Ok(Self {
            cluster,
            namespace: String::new(),
            custody_identity,
        })
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        // Namespace preparation/admission remains closed. This is a root-only
        // kernel and cannot substitute the root ring for namespace custody.
        if !self.namespace.is_empty() {
            return Err(Error::InvalidBinding);
        }
        let mut bytes = Vec::new();
        append_sized(&mut bytes, self.cluster.as_bytes())?;
        append_sized(&mut bytes, self.namespace.as_bytes())?;
        bytes.extend_from_slice(&self.custody_identity);
        Ok(bytes)
    }
}

pub(crate) struct RootKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RootKey").field(&"[REDACTED]").finish()
    }
}
impl RootKey {
    pub(crate) fn from_owned(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }
    fn capsule_key(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        // Separate the capsule wrapping key from the old HBA1 data key. The
        // original root/custody identity is stable across data-term rotations.
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.0.as_slice());
        let mut bytes: [u8; 32] = hmac::sign(&key, b"HeptaBao/root-keyring-capsule-key/v1\0")
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        let owned = Zeroizing::new(bytes);
        bytes.zeroize();
        Ok(owned)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RotationConfig {
    pub(crate) disabled: bool,
    pub(crate) max_operations: u64,
    pub(crate) interval: Duration,
}
impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            max_operations: MAX_OPERATIONS,
            interval: Duration::ZERO,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConfigPatch {
    pub(crate) enabled: Option<bool>,
    pub(crate) max_operations: Option<u64>,
    pub(crate) interval: Option<Duration>,
}
impl RotationConfig {
    pub(crate) fn with_patch(self, patch: ConfigPatch) -> Result<Self, Error> {
        let next = Self {
            disabled: patch.enabled.map_or(self.disabled, |enabled| !enabled),
            max_operations: patch.max_operations.unwrap_or(self.max_operations),
            interval: patch.interval.unwrap_or(self.interval),
        };
        next.validate()?;
        Ok(next)
    }
    fn validate(self) -> Result<(), Error> {
        if !(MIN_OPERATIONS..=MAX_OPERATIONS).contains(&self.max_operations)
            || self.interval != Duration::ZERO && self.interval < MIN_INTERVAL
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AutoReason {
    Operations,
    Interval,
}

struct DataKey {
    material: Zeroizing<[u8; 32]>,
    installed_at: Duration,
    encryptions: u64,
}
impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataKey")
            .field("installed_at", &self.installed_at)
            .field("encryptions", &self.encryptions)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

pub(crate) struct PreparedRing {
    binding: ScopeBinding,
    generation: u64,
    active_term: u32,
    keys: BTreeMap<u32, DataKey>,
    config: RotationConfig,
}
impl std::fmt::Debug for PreparedRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRing")
            .field("binding", &self.binding)
            .field("generation", &self.generation)
            .field("active_term", &self.active_term)
            .field("terms", &self.keys.keys().collect::<Vec<_>>())
            .field("config", &self.config)
            .finish()
    }
}
impl PreparedRing {
    /// This creates staged material only. The caller cannot derive a Service
    /// admission or a committed physical generation from this return value.
    pub(crate) fn bootstrap(
        root: &RootKey,
        binding: ScopeBinding,
        installed_at: Duration,
    ) -> Result<Self, Error> {
        binding.encode()?;
        let mut keys = BTreeMap::new();
        keys.insert(
            1,
            DataKey {
                material: Zeroizing::new(*root.0),
                installed_at: Duration::ZERO,
                encryptions: 0,
            },
        );
        keys.insert(
            2,
            DataKey {
                material: Zeroizing::new(crypto::random::<32>().map_err(|_| Error::Randomness)?),
                installed_at,
                encryptions: 0,
            },
        );
        let candidate = Self {
            binding,
            generation: 1,
            active_term: 2,
            keys,
            config: RotationConfig::default(),
        };
        candidate.validate()?;
        Ok(candidate)
    }
    pub(crate) fn config(&self) -> RotationConfig {
        self.config
    }
    pub(crate) fn set_config_candidate(&mut self, patch: ConfigPatch) -> Result<(), Error> {
        self.config = self.config.with_patch(patch)?;
        Ok(())
    }
    pub(crate) fn active_term(&self) -> u32 {
        self.active_term
    }
    pub(crate) fn active_encryptions(&self) -> Result<u64, Error> {
        self.keys
            .get(&self.active_term)
            .map(|key| key.encryptions)
            .ok_or(Error::InvalidTerm)
    }
    pub(crate) fn auto_reason(
        &self,
        original_authority_time: Duration,
    ) -> Result<Option<AutoReason>, Error> {
        if self.config.disabled {
            return Ok(None);
        }
        let key = self.keys.get(&self.active_term).ok_or(Error::InvalidTerm)?;
        if key.encryptions > self.config.max_operations {
            return Ok(Some(AutoReason::Operations));
        }
        if self.config.interval > Duration::ZERO
            && original_authority_time
                .checked_sub(key.installed_at)
                .is_some_and(|elapsed| elapsed > self.config.interval)
        {
            return Ok(Some(AutoReason::Interval));
        }
        Ok(None)
    }
    /// Manual staging is independent of Disabled. This never publishes or
    /// changes the predecessor; a real backend commit is still mandatory.
    pub(crate) fn prepare_manual_rotation(&self, installed_at: Duration) -> Result<Self, Error> {
        if installed_at
            < self
                .keys
                .get(&self.active_term)
                .ok_or(Error::InvalidTerm)?
                .installed_at
        {
            return Err(Error::ClockRegression);
        }
        if self.keys.len() >= MAX_KEYS {
            return Err(Error::Capacity);
        }
        let next_term = self.active_term.checked_add(1).ok_or(Error::Overflow)?;
        if self.keys.contains_key(&next_term) {
            return Err(Error::DuplicateTerm);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let mut keys = BTreeMap::new();
        for (&term, key) in &self.keys {
            keys.insert(
                term,
                DataKey {
                    material: Zeroizing::new(*key.material),
                    installed_at: key.installed_at,
                    encryptions: key.encryptions,
                },
            );
        }
        keys.insert(
            next_term,
            DataKey {
                material: Zeroizing::new(crypto::random::<32>().map_err(|_| Error::Randomness)?),
                installed_at,
                encryptions: 0,
            },
        );
        let candidate = Self {
            binding: self.binding.clone(),
            generation,
            active_term: next_term,
            keys,
            config: self.config,
        };
        candidate.validate()?;
        Ok(candidate)
    }
    pub(crate) fn seal_candidate(
        &mut self,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Successful AEAD work is counted even if a prepared generation is
        // subsequently withheld. No delivery/transaction failure refunds it.
        let output_capacity = plaintext
            .len()
            .checked_add(DATA_OVERHEAD)
            .ok_or(Error::Capacity)?;
        let header = data_header(self.active_term)?;
        let aad = data_aad(&self.binding, &header, context)?;
        let key = self
            .keys
            .get_mut(&self.active_term)
            .ok_or(Error::InvalidTerm)?;
        let next_count = key.encryptions.checked_add(1).ok_or(Error::Overflow)?;
        let protected = seal_hba1(&key.material, &aad, plaintext)?;
        key.encryptions = next_count;
        let mut bytes = Zeroizing::new(Vec::with_capacity(output_capacity));
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&protected[4..]);
        Ok(bytes)
    }
    pub(crate) fn open(
        &self,
        context: &[u8],
        protected: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if protected.starts_with(b"HBA1") {
            // One explicit legacy epoch; never try every key or rewrite the old
            // caller AAD. The legacy raw bytes remain decrypt-only.
            let key = self.keys.get(&1).ok_or(Error::UnknownTerm)?;
            return open_hba1(&key.material, context, protected);
        }
        if protected.len() < DATA_OVERHEAD {
            return Err(Error::InvalidFormat);
        }
        if &protected[..4] != DATA_MAGIC {
            return Err(Error::UnsupportedVersion);
        }
        let term = u32::from_be_bytes(
            protected[4..8]
                .try_into()
                .map_err(|_| Error::InvalidFormat)?,
        );
        if term <= 1 {
            return Err(Error::InvalidTerm);
        }
        let key = self.keys.get(&term).ok_or(Error::UnknownTerm)?;
        let aad = data_aad(&self.binding, &protected[..8], context)?;
        let mut old_framing = Zeroizing::new(Vec::with_capacity(protected.len() - 4));
        old_framing.extend_from_slice(b"HBA1");
        old_framing.extend_from_slice(&protected[8..]);
        open_hba1(&key.material, &aad, &old_framing)
    }
    pub(crate) fn root_sealed_capsule(&self, root: &RootKey) -> Result<Zeroizing<Vec<u8>>, Error> {
        let payload = self.encode_payload()?;
        seal_capsule_payload(root, &self.binding, self.generation, &payload)
    }
    pub(crate) fn from_root_sealed_capsule(
        root: &RootKey,
        expected_binding: ScopeBinding,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if bytes.len() < CAPSULE_HEADER_BYTES + 32 || bytes.len() > MAX_CAPSULE_BYTES {
            return Err(Error::InvalidFormat);
        }
        if &bytes[..4] != CAPSULE_MAGIC {
            return Err(Error::UnsupportedVersion);
        }
        if bytes[4] != CAPSULE_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let generation =
            u64::from_be_bytes(bytes[5..13].try_into().map_err(|_| Error::InvalidFormat)?);
        if generation == 0 {
            return Err(Error::InvalidFormat);
        }
        let aad = capsule_aad(&expected_binding, &bytes[..CAPSULE_HEADER_BYTES])?;
        let wrap_key = root.capsule_key()?;
        let plaintext = open_hba1(&wrap_key, &aad, &bytes[CAPSULE_HEADER_BYTES..])?;
        Self::decode_payload(expected_binding, generation, &plaintext)
    }
    fn encode_payload(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.active_term.to_be_bytes());
        out.push(u8::from(self.config.disabled));
        out.extend_from_slice(&self.config.max_operations.to_be_bytes());
        append_duration(&mut out, self.config.interval);
        out.extend_from_slice(
            &u16::try_from(self.keys.len())
                .map_err(|_| Error::Capacity)?
                .to_be_bytes(),
        );
        for (&term, key) in &self.keys {
            out.extend_from_slice(&term.to_be_bytes());
            append_duration(&mut out, key.installed_at);
            out.extend_from_slice(&key.encryptions.to_be_bytes());
            out.extend_from_slice(key.material.as_slice());
        }
        if out
            .len()
            .checked_add(CAPSULE_HEADER_BYTES + 32)
            .is_none_or(|size| size > MAX_CAPSULE_BYTES)
        {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
    fn decode_payload(binding: ScopeBinding, generation: u64, bytes: &[u8]) -> Result<Self, Error> {
        let mut input = Cursor { bytes, offset: 0 };
        if input.u16()? != PAYLOAD_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if input.u64()? != generation {
            return Err(Error::Authentication);
        }
        let active_term = input.u32()?;
        let disabled = match input.byte()? {
            0 => false,
            1 => true,
            _ => return Err(Error::InvalidFormat),
        };
        let config = RotationConfig {
            disabled,
            max_operations: input.u64()?,
            interval: input.duration()?,
        };
        config.validate()?;
        let count = usize::from(input.u16()?);
        if !(2..=MAX_KEYS).contains(&count) {
            return Err(Error::Capacity);
        }
        let mut keys = BTreeMap::new();
        for _ in 0..count {
            let term = input.u32()?;
            if term == 0 {
                return Err(Error::InvalidTerm);
            }
            if keys.contains_key(&term) {
                return Err(Error::DuplicateTerm);
            }
            let installed_at = input.duration()?;
            let encryptions = input.u64()?;
            let material: Zeroizing<[u8; 32]> = Zeroizing::new(
                input
                    .take(32)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat)?,
            );
            keys.insert(
                term,
                DataKey {
                    material,
                    installed_at,
                    encryptions,
                },
            );
        }
        if input.offset != bytes.len() {
            return Err(Error::InvalidFormat);
        }
        let ring = Self {
            binding,
            generation,
            active_term,
            keys,
            config,
        };
        ring.validate()?;
        Ok(ring)
    }
    fn validate(&self) -> Result<(), Error> {
        self.binding.encode()?;
        self.config.validate()?;
        if self.generation == 0
            || self.active_term <= 1
            || self.keys.len() < 2
            || self.keys.len() > MAX_KEYS
            || usize::try_from(self.active_term).map_or(true, |term| term != self.keys.len())
            || !self.keys.contains_key(&1)
            || !self.keys.contains_key(&self.active_term)
            || self
                .keys
                .keys()
                .any(|term| *term == 0 || *term > self.active_term)
        {
            return Err(Error::InvalidTerm);
        }
        let terms = self.keys.values().collect::<Vec<_>>();
        for (index, key) in terms.iter().enumerate() {
            if terms[index + 1..]
                .iter()
                .any(|other| bool::from(key.material.as_slice().ct_eq(other.material.as_slice())))
            {
                return Err(Error::DuplicateMaterial);
            }
        }
        Ok(())
    }
}
fn data_header(term: u32) -> Result<[u8; 8], Error> {
    if term <= 1 {
        return Err(Error::InvalidTerm);
    }
    let mut header = [0; 8];
    header[..4].copy_from_slice(DATA_MAGIC);
    header[4..].copy_from_slice(&term.to_be_bytes());
    Ok(header)
}
fn append_sized(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Capacity)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
fn data_aad(binding: &ScopeBinding, header: &[u8], context: &[u8]) -> Result<Vec<u8>, Error> {
    if header.len() != 8 || context.len() > MAX_CONTEXT_BYTES {
        return Err(Error::Capacity);
    }
    let mut out = b"HeptaBao/data-term-envelope/v2\0".to_vec();
    append_sized(&mut out, &binding.encode()?)?;
    append_sized(&mut out, header)?;
    append_sized(&mut out, context)?;
    Ok(out)
}
fn capsule_aad(binding: &ScopeBinding, header: &[u8]) -> Result<Vec<u8>, Error> {
    if header.len() != CAPSULE_HEADER_BYTES {
        return Err(Error::InvalidFormat);
    }
    let mut out = b"HeptaBao/root-sealed-keyring/v1\0".to_vec();
    append_sized(&mut out, &binding.encode()?)?;
    append_sized(&mut out, header)?;
    Ok(out)
}
fn seal_capsule_payload(
    root: &RootKey,
    binding: &ScopeBinding,
    generation: u64,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if generation == 0
        || payload
            .len()
            .checked_add(CAPSULE_HEADER_BYTES + 32)
            .is_none_or(|n| n > MAX_CAPSULE_BYTES)
    {
        return Err(Error::Capacity);
    }
    let mut header = Vec::with_capacity(CAPSULE_HEADER_BYTES);
    header.extend_from_slice(CAPSULE_MAGIC);
    header.push(CAPSULE_VERSION);
    header.extend_from_slice(&generation.to_be_bytes());
    let aad = capsule_aad(binding, &header)?;
    let wrap_key = root.capsule_key()?;
    let protected = seal_hba1(&wrap_key, &aad, payload)?;
    let mut bytes = Zeroizing::new(header);
    bytes.extend_from_slice(&protected);
    Ok(bytes)
}
fn seal_hba1(
    key: &[u8; 32],
    context: &[u8],
    plaintext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let nonce = crypto::random::<12>().map_err(|_| Error::Randomness)?;
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Authentication)?;
    let cipher = aead::LessSafeKey::new(unbound);
    let mut output = Zeroizing::new(plaintext.to_vec());
    cipher
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context),
            &mut *output,
        )
        .map_err(|_| Error::Authentication)?;
    let mut protected = Zeroizing::new(Vec::with_capacity(
        output.len().checked_add(16).ok_or(Error::Capacity)?,
    ));
    protected.extend_from_slice(b"HBA1");
    protected.extend_from_slice(&nonce);
    protected.extend_from_slice(&output);
    Ok(protected)
}
fn open_hba1(
    key: &[u8; 32],
    context: &[u8],
    protected: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if protected.len() < 32 || !protected.starts_with(b"HBA1") {
        return Err(Error::InvalidFormat);
    }
    let nonce: [u8; 12] = protected[4..16]
        .try_into()
        .map_err(|_| Error::InvalidFormat)?;
    let unbound =
        aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| Error::Authentication)?;
    let cipher = aead::LessSafeKey::new(unbound);
    let mut bytes = Zeroizing::new(protected[16..].to_vec());
    let plain = cipher
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context),
            &mut bytes,
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plain.to_vec()))
}
fn append_duration(out: &mut Vec<u8>, duration: Duration) {
    out.extend_from_slice(&duration.as_secs().to_be_bytes());
    out.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
}
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(count).ok_or(Error::Overflow)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidFormat)?;
        self.offset = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::InvalidFormat)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::InvalidFormat)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::InvalidFormat)?,
        ))
    }
    fn duration(&mut self) -> Result<Duration, Error> {
        let seconds = self.u64()?;
        let nanos = self.u32()?;
        if nanos >= 1_000_000_000 {
            return Err(Error::InvalidFormat);
        }
        Ok(Duration::new(seconds, nanos))
    }
}

#[cfg(test)]
#[path = "crypto_rotation_preparation_tests.rs"]
mod tests;
