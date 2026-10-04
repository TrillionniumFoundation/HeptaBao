//! Independent namespace custody primitives. This module creates authenticated
//! ciphertext and process-local unseal progress; it grants no request authority.
//! Namespace owner partition, publication, record storage and peer key transport
//! remain Service responsibilities. These primitives do not seal a namespace by
//! changing an HTTP routing flag.
use crate::crypto::{self, AeadBarrier};
use base64::{Engine, engine::general_purpose::STANDARD};
use heptabao_durable_service::Barrier;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[path = "namespace_custody_inherited.rs"]
mod inherited;
pub use inherited::{InheritedDescriptor, InheritedParent};

const VERSION: u32 = 1;
const CUSTODY_SCHEMA: u32 = 81;
const MAX_PAYLOAD: usize = crate::MAX_APPLICATION_STATE_BYTES;
const MAX_CIPHERTEXT: usize = MAX_PAYLOAD + 32;
const MAX_ENCODING: usize = MAX_CIPHERTEXT.div_ceil(3) * 4;

/// Actual namespace owner metadata. None of these fields is an authority token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    cluster_id: String,
    namespace: String,
    namespace_id: String,
    incarnation: u64,
}

impl Binding {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn incarnation(&self) -> u64 {
        self.incarnation
    }

    pub fn new(
        cluster_id: String,
        namespace: String,
        namespace_id: String,
        incarnation: u64,
    ) -> Result<Self, Error> {
        let binding = Self {
            cluster_id,
            namespace,
            namespace_id,
            incarnation,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.cluster_id.is_empty()
            || self.cluster_id.len() > 128
            || self.cluster_id.chars().any(char::is_control)
            || self.namespace_id.is_empty()
            || self.namespace_id.len() > 128
            || self.namespace_id.chars().any(char::is_control)
            || self.incarnation == 0
            || self.namespace.is_empty()
            || self.namespace.len() > 512
            || self.namespace.split('/').any(|segment| {
                segment.is_empty()
                    || segment.len() > 128
                    || matches!(segment, "." | "..")
                    || segment
                        .bytes()
                        .any(|byte| !byte.is_ascii_alphanumeric() && !b"_-.".contains(&byte))
            })
        {
            return Err(Error::InvalidBinding);
        }
        Ok(())
    }
}

/// Durable namespace ciphertext. Keys and partial unseal shares are excluded.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    version: u32,
    schema: u32,
    binding: Binding,
    shares: u8,
    threshold: u8,
    key_epoch: u64,
    generation: u64,
    seal_frontier: u64,
    wrapped_key: String,
    protected_assets: String,
}

impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceCustodyDescriptor")
            .field("version", &self.version)
            .field("schema", &self.schema)
            .field("binding", &self.binding)
            .field("shares", &self.shares)
            .field("threshold", &self.threshold)
            .field("key_epoch", &self.key_epoch)
            .field("generation", &self.generation)
            .field("seal_frontier", &self.seal_frontier)
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidBinding,
    InvalidCounts,
    InvalidShare,
    InvalidKey,
    CorruptDescriptor,
    AssetCapacity,
    GenerationExhausted,
    Randomness,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "namespace custody {:?}", self)
    }
}
impl std::error::Error for Error {}

/// A process-local authenticated namespace key; never serializable or cloneable.
pub struct Key {
    binding: Binding,
    key_epoch: u64,
    bytes: Zeroizing<[u8; 32]>,
}
impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceCustodyKey")
            .field("binding", &self.binding)
            .field("key_epoch", &self.key_epoch)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Key {
    pub(crate) fn binding(&self) -> &Binding {
        &self.binding
    }

    pub(crate) fn matches_binding(&self, actual: &Binding) -> bool {
        self.binding == *actual
    }
    pub(crate) fn owns_namespace(&self, namespace: &str) -> bool {
        namespace == self.binding.namespace
            || namespace
                .strip_prefix(&self.binding.namespace)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
    fn record_context(&self, namespace: &str, id: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if !self.owns_namespace(namespace) {
            return Err(Error::InvalidBinding);
        }
        let binding = serde_json::to_vec(&self.binding).map_err(|_| Error::InvalidBinding)?;
        let mut context = b"heptabao-namespace-record-object-v1\0".to_vec();
        context.extend_from_slice(&(binding.len() as u64).to_be_bytes());
        context.extend_from_slice(&binding);
        context.extend_from_slice(&self.key_epoch.to_be_bytes());
        context.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
        context.extend_from_slice(namespace.as_bytes());
        context.extend_from_slice(id);
        Ok(context)
    }

    /// Independent keyed object addresses cannot reveal private path/value
    /// hashes to the root owner. This derivation never exposes the barrier key.
    pub(crate) fn record_address_key(
        &self,
        namespace: &str,
    ) -> Result<std::sync::Arc<crate::state_records::AddressKey>, Error> {
        let context = self.record_context(namespace, &[0; 32])?;
        let mac = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.bytes.as_slice());
        let digest: [u8; 32] = ring::hmac::sign(&mac, &context)
            .as_ref()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        Ok(crate::state_records::AddressKey::from_bytes(digest))
    }

    pub(crate) fn protect_record_object(
        &self,
        namespace: &str,
        id: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        // Every original graph object is bounded by the existing block/page
        // codec. This is object encryption, never whole-record flattening.
        if bytes.is_empty() || bytes.len() > crate::state_records::BLOCK_BYTES + 25 {
            return Err(Error::AssetCapacity);
        }
        let barrier = AeadBarrier::new(*self.bytes).map_err(|_| Error::InvalidKey)?;
        barrier
            .seal(&self.record_context(namespace, id)?, bytes)
            .map(Zeroizing::new)
            .map_err(|_| Error::Randomness)
    }

    pub(crate) fn open_record_object(
        &self,
        namespace: &str,
        id: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if bytes.len() <= 32 || bytes.len() > crate::state_records::BLOCK_BYTES + 25 + 32 {
            return Err(Error::CorruptDescriptor);
        }
        let barrier = AeadBarrier::new(*self.bytes).map_err(|_| Error::InvalidKey)?;
        barrier
            .open(&self.record_context(namespace, id)?, bytes)
            .map(Zeroizing::new)
            .map_err(|_| Error::CorruptDescriptor)
    }
}

/// Fresh shares must be delivered privately after the actual owner commits.
/// This value must never be serialized into a durable owner, template or audit.
pub struct Created {
    pub descriptor: Descriptor,
    pub shares: Vec<Zeroizing<Vec<u8>>>,
}
impl std::fmt::Debug for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceCustodyCreated")
            .field("descriptor", &self.descriptor)
            .field("share_count", &self.shares.len())
            .field("share_bytes", &"[REDACTED]")
            .finish()
    }
}

impl Descriptor {
    pub fn create(
        binding: Binding,
        shares: u8,
        threshold: u8,
        assets: &[u8],
    ) -> Result<Created, Error> {
        binding.validate()?;
        validate_counts(shares, threshold)?;
        validate_assets(assets)?;
        let seal_key = Zeroizing::new(crypto::random::<32>().map_err(|_| Error::Randomness)?);
        let barrier_key = Zeroizing::new(crypto::random::<32>().map_err(|_| Error::Randomness)?);
        let parts =
            crypto::split_secret(&seal_key, shares, threshold).map_err(|_| Error::Randomness)?;
        let mut descriptor = Self {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding,
            shares,
            threshold,
            key_epoch: 1,
            generation: 1,
            seal_frontier: 1,
            wrapped_key: String::new(),
            protected_assets: String::new(),
        };
        let wrapped = crypto::wrap_barrier_key(
            &seal_key,
            &descriptor.context(b"seal-key-wrapping", false)?,
            &barrier_key,
        )
        .map_err(|_| Error::Randomness)?;
        descriptor.wrapped_key = STANDARD.encode(wrapped);
        let barrier = AeadBarrier::new(*barrier_key).map_err(|_| Error::InvalidKey)?;
        let protected = barrier
            .seal(&descriptor.context(b"namespace-assets", true)?, assets)
            .map_err(|_| Error::Randomness)?;
        descriptor.protected_assets = STANDARD.encode(protected);
        descriptor.validate(&descriptor.binding)?;
        let shares = parts
            .iter()
            .map(|part| Zeroizing::new(part.encode_indexed()))
            .collect();
        Ok(Created { descriptor, shares })
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }
    pub(crate) fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn seal_frontier(&self) -> u64 {
        self.seal_frontier
    }
    pub fn share_count(&self) -> u8 {
        self.shares
    }
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn validate(&self, actual: &Binding) -> Result<(), Error> {
        actual.validate()?;
        validate_counts(self.shares, self.threshold)?;
        if self.version != VERSION
            || self.schema != CUSTODY_SCHEMA
            || self.binding != *actual
            || self.key_epoch == 0
            || self.generation == 0
            || self.seal_frontier == 0
            || self.wrapped_key.len() > 128
            || self.protected_assets.len() > MAX_ENCODING
        {
            return Err(Error::CorruptDescriptor);
        }
        let wrapped = STANDARD
            .decode(&self.wrapped_key)
            .map_err(|_| Error::CorruptDescriptor)?;
        let protected = STANDARD
            .decode(&self.protected_assets)
            .map_err(|_| Error::CorruptDescriptor)?;
        if wrapped.len() != 64
            || !wrapped.starts_with(b"HBK1")
            || protected.len() <= 32
            || protected.len() > MAX_CIPHERTEXT
            || !protected.starts_with(b"HBA1")
        {
            return Err(Error::CorruptDescriptor);
        }
        Ok(())
    }

    fn context(&self, purpose: &[u8], include_generation: bool) -> Result<Vec<u8>, Error> {
        let binding = serde_json::to_vec(&self.binding).map_err(|_| Error::InvalidBinding)?;
        let mut context = Vec::with_capacity(binding.len() + 128);
        for field in [
            b"heptabao-independent-namespace-custody-v1".as_slice(),
            purpose,
            &binding,
        ] {
            context.extend_from_slice(&(field.len() as u64).to_be_bytes());
            context.extend_from_slice(field);
        }
        context.extend_from_slice(&self.version.to_be_bytes());
        context.extend_from_slice(&self.schema.to_be_bytes());
        context.extend_from_slice(&[self.shares, self.threshold]);
        context.extend_from_slice(&self.key_epoch.to_be_bytes());
        if include_generation {
            context.extend_from_slice(&self.generation.to_be_bytes());
            context.extend_from_slice(&self.seal_frontier.to_be_bytes());
        }
        Ok(context)
    }

    pub fn open_assets(&self, actual: &Binding, key: &Key) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate(actual)?;
        if key.binding != *actual || key.key_epoch != self.key_epoch {
            return Err(Error::InvalidKey);
        }
        let barrier = AeadBarrier::new(*key.bytes).map_err(|_| Error::InvalidKey)?;
        let protected = STANDARD
            .decode(&self.protected_assets)
            .map_err(|_| Error::CorruptDescriptor)?;
        let assets = Zeroizing::new(
            barrier
                .open(&self.context(b"namespace-assets", true)?, &protected)
                .map_err(|_| Error::CorruptDescriptor)?,
        );
        validate_assets(&assets)?;
        Ok(assets)
    }

    /// Reprotect a typed owner's serialized assets at the next generation.
    /// The caller must publish the new descriptor and all owner removals together.
    pub fn replace_assets(
        &self,
        actual: &Binding,
        key: &Key,
        assets: &[u8],
    ) -> Result<Self, Error> {
        // Authenticate the predecessor before carrying its wrapped key forward.
        let _previous = self.open_assets(actual, key)?;
        validate_assets(assets)?;
        let mut next = self.clone();
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let barrier = AeadBarrier::new(*key.bytes).map_err(|_| Error::InvalidKey)?;
        let protected = barrier
            .seal(&next.context(b"namespace-assets", true)?, assets)
            .map_err(|_| Error::Randomness)?;
        next.protected_assets = STANDARD.encode(protected);
        Ok(next)
    }

    /// Manual closure advances the authenticated frontier. Existing unseal
    /// shares remain valid; stale progress and peer/effect capabilities do not.
    pub fn advance_seal_frontier(&self, actual: &Binding, key: &Key) -> Result<Self, Error> {
        let assets = self.open_assets(actual, key)?;
        let mut next = self.clone();
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        next.seal_frontier = self
            .seal_frontier
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        let barrier = AeadBarrier::new(*key.bytes).map_err(|_| Error::InvalidKey)?;
        next.protected_assets = STANDARD.encode(
            barrier
                .seal(&next.context(b"namespace-assets", true)?, &assets)
                .map_err(|_| Error::Randomness)?,
        );
        Ok(next)
    }

    pub(crate) fn frontier(&self) -> Frontier {
        Frontier {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding: self.binding.clone(),
            key_epoch: self.key_epoch,
            generation: self.generation,
            seal_frontier: self.seal_frontier,
            retired: false,
            descriptor_digest: self.frontier_digest(),
        }
    }

    fn frontier_digest(&self) -> String {
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        digest.update(b"heptabao-namespace-durable-floor-descriptor-v1\0");
        for value in [
            self.binding.cluster_id.as_bytes(),
            self.binding.namespace.as_bytes(),
            self.binding.namespace_id.as_bytes(),
            self.wrapped_key.as_bytes(),
            self.protected_assets.as_bytes(),
        ] {
            digest.update(&(value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        digest.update(&self.version.to_be_bytes());
        digest.update(&self.schema.to_be_bytes());
        digest.update(&[self.shares, self.threshold]);
        for value in [
            self.binding.incarnation,
            self.key_epoch,
            self.generation,
            self.seal_frontier,
        ] {
            digest.update(&value.to_be_bytes());
        }
        digest
            .finish()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub(crate) fn admits_successor(&self, next: &Self) -> bool {
        self.binding == next.binding
            && self.key_epoch == next.key_epoch
            && next.generation >= self.generation
            && next.seal_frontier >= self.seal_frontier
            && (next.generation != self.generation || self == next)
    }

    pub(crate) fn retirement(&self) -> Tombstone {
        Tombstone {
            version: VERSION,
            schema: CUSTODY_SCHEMA,
            binding: self.binding.clone(),
            key_epoch: self.key_epoch,
            seal_frontier: self.seal_frontier,
        }
    }
}

/// Private durable floor retained when a parent's encrypted catalog hides
/// this actual child. It is not a catalog entry and grants no routing authority.
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frontier {
    version: u32,
    schema: u32,
    binding: Binding,
    key_epoch: u64,
    generation: u64,
    seal_frontier: u64,
    retired: bool,
    descriptor_digest: String,
}
impl Frontier {
    pub(crate) fn matches_binding(&self, binding: &Binding) -> bool {
        self.binding == *binding
    }
    pub(crate) fn incarnation(&self) -> u64 {
        self.binding.incarnation
    }
    pub(crate) fn validate(&self, cluster: &str, path: &str, id: &str) -> Result<(), Error> {
        self.binding.validate()?;
        if self.version != VERSION
            || self.schema != CUSTODY_SCHEMA
            || self.binding.cluster_id != cluster
            || self.binding.namespace != path
            || self.binding.namespace_id != id
            || self.key_epoch == 0
            || self.generation == 0
            || self.seal_frontier == 0
            || self.descriptor_digest.len() != 64
            || self
                .descriptor_digest
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(Error::CorruptDescriptor);
        }
        Ok(())
    }
    pub(crate) fn admits(&self, next: &Self) -> bool {
        if self.binding == next.binding {
            self.key_epoch == next.key_epoch
                && next.generation >= self.generation
                && next.seal_frontier >= self.seal_frontier
                && (!self.retired || next.retired)
                && (next.generation != self.generation
                    || self.descriptor_digest == next.descriptor_digest)
        } else {
            self.retired
                && !next.retired
                && self.binding.cluster_id == next.binding.cluster_id
                && self.binding.namespace == next.binding.namespace
                && next.binding.incarnation > self.binding.incarnation
        }
    }
    pub(crate) fn retirement(&self) -> Self {
        let mut next = self.clone();
        next.retired = true;
        next
    }
    pub(crate) fn is_retired(&self) -> bool {
        self.retired
    }
    pub(crate) fn matches_retirement(&self, tombstone: &Tombstone) -> bool {
        self.retired
            && self.binding == tombstone.binding
            && self.key_epoch == tombstone.key_epoch
            && self.seal_frontier == tombstone.seal_frontier
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tombstone {
    version: u32,
    schema: u32,
    binding: Binding,
    key_epoch: u64,
    seal_frontier: u64,
}

impl Tombstone {
    pub(crate) fn admits(&self, next: &Self) -> bool {
        if self.binding == next.binding {
            self.key_epoch == next.key_epoch && next.seal_frontier >= self.seal_frontier
        } else {
            self.binding.cluster_id == next.binding.cluster_id
                && self.binding.namespace == next.binding.namespace
                && next.binding.incarnation > self.binding.incarnation
        }
    }

    pub(crate) fn validate(
        &self,
        cluster_id: &str,
        namespace: &str,
        next_incarnation: u64,
    ) -> Result<(), Error> {
        self.binding.validate()?;
        if self.version != VERSION
            || self.schema != CUSTODY_SCHEMA
            || self.key_epoch == 0
            || self.seal_frontier == 0
            || self.binding.cluster_id != cluster_id
            || self.binding.namespace != namespace
            || self.binding.incarnation >= next_incarnation
        {
            return Err(Error::CorruptDescriptor);
        }
        Ok(())
    }
}

fn validate_counts(shares: u8, threshold: u8) -> Result<(), Error> {
    if shares == 0 || threshold == 0 || threshold > shares || shares > 1 && threshold == 1 {
        return Err(Error::InvalidCounts);
    }
    Ok(())
}
fn validate_assets(assets: &[u8]) -> Result<(), Error> {
    if assets.is_empty() || assets.len() > MAX_PAYLOAD {
        return Err(Error::AssetCapacity);
    }
    Ok(())
}

/// Runtime-only progress. Raw valid-length fragments may count before threshold
/// authentication, matching the actual official namespace unseal boundary.
pub struct Progress {
    actual: Binding,
    key_epoch: u64,
    seal_frontier: u64,
    shares: u8,
    threshold: u8,
    parts: Vec<Zeroizing<Vec<u8>>>,
    nonce: String,
}
impl std::fmt::Debug for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceUnsealProgress")
            .field("actual", &self.actual)
            .field("progress", &self.parts.len())
            .field("threshold", &self.threshold)
            .field("parts", &"[REDACTED]")
            .finish()
    }
}

pub enum Submission {
    Pending,
    Unlocked {
        key: Key,
        assets: Zeroizing<Vec<u8>>,
    },
}
impl std::fmt::Debug for Submission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Unlocked { .. } => {
                f.write_str("Unlocked { key: [REDACTED], assets: [REDACTED] }")
            }
        }
    }
}

impl Progress {
    pub fn new(actual: Binding, descriptor: &Descriptor) -> Result<Self, Error> {
        descriptor.validate(&actual)?;
        Ok(Self {
            actual,
            key_epoch: descriptor.key_epoch,
            seal_frontier: descriptor.seal_frontier,
            shares: descriptor.shares,
            threshold: descriptor.threshold,
            parts: Vec::new(),
            nonce: String::new(),
        })
    }
    pub fn count(&self) -> usize {
        self.parts.len()
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn reset(&mut self) {
        self.parts.clear();
        self.nonce.clear();
    }

    pub fn submit(
        &mut self,
        descriptor: &Descriptor,
        fragment: &[u8],
    ) -> Result<Submission, Error> {
        descriptor.validate(&self.actual)?;
        if self.key_epoch != descriptor.key_epoch
            || self.seal_frontier != descriptor.seal_frontier
            || self.shares != descriptor.shares
            || self.threshold != descriptor.threshold
        {
            self.reset();
            return Err(Error::CorruptDescriptor);
        }
        let expected = if self.threshold == 1 { 32 } else { 33 };
        if fragment.len() != expected {
            return Err(Error::InvalidShare);
        }
        if self.parts.iter().any(|part| part.as_slice() == fragment) {
            return Ok(Submission::Pending);
        }
        if self.parts.is_empty() {
            self.nonce = nonce()?;
        }
        self.parts.push(Zeroizing::new(fragment.to_vec()));
        if self.parts.len() < usize::from(self.threshold) {
            return Ok(Submission::Pending);
        }
        let result = self.authenticate(descriptor);
        // Both successful and unsuccessful threshold attempts retire all parts.
        self.reset();
        result
    }

    fn authenticate(&self, descriptor: &Descriptor) -> Result<Submission, Error> {
        let selected = self
            .parts
            .iter()
            .map(|part| {
                crypto::SecretShare::decode_indexed(part, self.shares, self.threshold)
                    .map_err(|_| Error::InvalidKey)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let seal_key =
            Zeroizing::new(crypto::combine_shares(&selected).map_err(|_| Error::InvalidKey)?);
        let wrapped = STANDARD
            .decode(&descriptor.wrapped_key)
            .map_err(|_| Error::CorruptDescriptor)?;
        let bytes = Zeroizing::new(
            crypto::unwrap_barrier_key(
                &seal_key,
                &descriptor.context(b"seal-key-wrapping", false)?,
                &wrapped,
            )
            .map_err(|_| Error::InvalidKey)?,
        );
        let key = Key {
            binding: self.actual.clone(),
            key_epoch: self.key_epoch,
            bytes,
        };
        let assets = descriptor.open_assets(&self.actual, &key)?;
        Ok(Submission::Unlocked { key, assets })
    }
}

fn nonce() -> Result<String, Error> {
    let mut bytes = crypto::random::<16>().map_err(|_| Error::Randomness)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_manual_frontier_retires_stale_progress_and_authenticates_new_assets()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = Binding::new(
            "frontier-cluster".into(),
            "custody".into(),
            "public-id".into(),
            1,
        )?;
        let created = Descriptor::create(binding.clone(), 3, 2, b"{\"typed\":\"private-assets\"}")?;
        let mut stale = Progress::new(binding.clone(), &created.descriptor)?;
        assert!(
            matches!(
                stale.submit(&created.descriptor, &created.shares[0])?,
                Submission::Pending
            ),
            "old progress started"
        );
        let mut unlock = Progress::new(binding.clone(), &created.descriptor)?;
        unlock.submit(&created.descriptor, &created.shares[0])?;
        let key = match unlock.submit(&created.descriptor, &created.shares[1])? {
            Submission::Unlocked { key, .. } => key,
            Submission::Pending => return Err("threshold".into()),
        };
        let closed = created.descriptor.advance_seal_frontier(&binding, &key)?;
        assert!(
            closed.seal_frontier() == created.descriptor.seal_frontier() + 1
                && closed.generation() == created.descriptor.generation() + 1,
            "manual seal advances authenticated monotone frontier"
        );
        assert!(
            stale.submit(&closed, &created.shares[1]).is_err()
                && stale.count() == 0
                && stale.nonce().is_empty(),
            "stale partial progress cannot cross manual frontier"
        );
        let mut fresh = Progress::new(binding.clone(), &closed)?;
        fresh.submit(&closed, &created.shares[0])?;
        let assets = match fresh.submit(&closed, &created.shares[1])? {
            Submission::Unlocked { assets, .. } => assets,
            Submission::Pending => return Err("new threshold".into()),
        };
        assert!(
            assets.as_slice() == b"{\"typed\":\"private-assets\"}",
            "same private shares authenticate latest closed owner"
        );
        let mut tampered = closed.clone();
        tampered.seal_frontier -= 1;
        assert!(
            tampered.open_assets(&binding, &key).is_err(),
            "frontier is part of authenticated asset AAD"
        );
        Ok(())
    }
    fn binding(namespace: &str, incarnation: u64) -> Result<Binding, Error> {
        Binding::new(
            "fixture-cluster".into(),
            namespace.into(),
            "fixture-public-id".into(),
            incarnation,
        )
    }
    fn unlock(created: &Created) -> Result<(Key, Zeroizing<Vec<u8>>), Error> {
        let mut progress = Progress::new(created.descriptor.binding.clone(), &created.descriptor)?;
        for part in &created.shares {
            if let Submission::Unlocked { key, assets } =
                progress.submit(&created.descriptor, part)?
            {
                return Ok((key, assets));
            }
        }
        Err(Error::InvalidKey)
    }

    #[test]
    fn threshold_duplicate_reset_and_private_storage() -> Result<(), Box<dyn std::error::Error>> {
        let actual = binding("parent/child", 7)?;
        let created =
            Descriptor::create(actual.clone(), 3, 2, b"private fixture namespace CA key")?;
        let wire = serde_json::to_vec(&created.descriptor)?;
        assert!(
            !wire
                .windows(20)
                .any(|chunk| chunk == b"private fixture name")
        );
        assert!(!format!("{created:?}").contains("private fixture namespace CA key"));
        let mut progress = Progress::new(actual, &created.descriptor)?;
        assert!(matches!(
            progress.submit(&created.descriptor, &created.shares[0])?,
            Submission::Pending
        ));
        assert_eq!(progress.count(), 1);
        let nonce = progress.nonce().to_owned();
        assert!(matches!(
            progress.submit(&created.descriptor, &created.shares[0])?,
            Submission::Pending
        ));
        assert_eq!(progress.count(), 1);
        assert_eq!(progress.nonce(), nonce);
        progress.reset();
        assert_eq!(progress.count(), 0);
        assert!(progress.nonce().is_empty());
        assert!(matches!(
            progress.submit(&created.descriptor, &created.shares[1])?,
            Submission::Pending
        ));
        let Submission::Unlocked { key, assets } =
            progress.submit(&created.descriptor, &created.shares[2])?
        else {
            return Err("threshold did not unlock".into());
        };
        assert_eq!(assets.as_slice(), b"private fixture namespace CA key");
        assert_eq!(progress.count(), 0);
        assert!(progress.nonce().is_empty());
        assert!(!format!("{key:?}").contains("private fixture namespace CA key"));
        Ok(())
    }

    #[test]
    fn wrong_namespace_incarnation_cluster_and_counts_cannot_open()
    -> Result<(), Box<dyn std::error::Error>> {
        let created = Descriptor::create(binding("alpha", 1)?, 3, 2, b"retained namespace assets")?;
        let (key, _) = unlock(&created)?;
        for actual in [
            binding("beta", 1)?,
            binding("alpha", 2)?,
            Binding::new(
                "other-cluster".into(),
                "alpha".into(),
                "fixture-public-id".into(),
                1,
            )?,
        ] {
            assert!(created.descriptor.open_assets(&actual, &key).is_err());
        }
        let mut changed = created.descriptor.clone();
        changed.shares = 4;
        let mut progress = Progress::new(changed.binding.clone(), &changed)?;
        assert!(matches!(
            progress.submit(&changed, &created.shares[0])?,
            Submission::Pending
        ));
        assert!(progress.submit(&changed, &created.shares[1]).is_err());
        assert_eq!(progress.count(), 0);
        Ok(())
    }

    #[test]
    fn wrong_threshold_key_and_corrupt_ciphertext_fail_without_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let created = Descriptor::create(binding("alpha", 1)?, 3, 2, b"retained namespace assets")?;
        let wrong = Descriptor::create(binding("alpha", 1)?, 3, 2, b"other namespace assets")?;
        let mut progress = Progress::new(created.descriptor.binding.clone(), &created.descriptor)?;
        assert!(matches!(
            progress.submit(&created.descriptor, &wrong.shares[0])?,
            Submission::Pending
        ));
        assert!(
            progress
                .submit(&created.descriptor, &wrong.shares[1])
                .is_err()
        );
        assert_eq!(progress.count(), 0);
        assert!(progress.nonce().is_empty());
        let mut corrupted = created.descriptor.clone();
        let mut bytes = STANDARD.decode(&corrupted.protected_assets)?;
        bytes[20] ^= 1;
        corrupted.protected_assets = STANDARD.encode(bytes);
        let mut progress = Progress::new(corrupted.binding.clone(), &corrupted)?;
        assert!(matches!(
            progress.submit(&corrupted, &created.shares[0])?,
            Submission::Pending
        ));
        assert!(progress.submit(&corrupted, &created.shares[1]).is_err());
        assert_eq!(progress.count(), 0);
        Ok(())
    }

    #[test]
    fn generations_authenticate_ciphertext_and_key_stays_runtime_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let created = Descriptor::create(binding("parent/child", 5)?, 1, 1, b"first owned assets")?;
        let (key, assets) = unlock(&created)?;
        assert_eq!(assets.as_slice(), b"first owned assets");
        let next = created.descriptor.replace_assets(
            created.descriptor.binding(),
            &key,
            b"second owned assets",
        )?;
        assert_eq!(next.generation(), 2);
        assert_eq!(
            next.open_assets(next.binding(), &key)?.as_slice(),
            b"second owned assets"
        );
        let mut switched = next.clone();
        switched.generation = 1;
        assert!(switched.open_assets(switched.binding(), &key).is_err());
        let wire = serde_json::to_value(&next)?;
        assert!(wire.get("parts").is_none());
        assert!(wire.get("nonce").is_none());
        assert!(wire.get("key").is_none());
        let encoded = serde_json::to_vec(&next)?;
        let reopened: Descriptor = serde_json::from_slice(&encoded)?;
        let migrated = Created {
            descriptor: reopened,
            shares: created.shares,
        };
        let (_, assets) = unlock(&migrated)?;
        assert_eq!(assets.as_slice(), b"second owned assets");
        Ok(())
    }
}
