//! Shared-key encryption and an authenticated external V6 object directory.
//!
//! This module is a child of `ha_state`: it uses the actual configured replication
//! key, never the node's local Shamir barrier key. Ciphertext, directory pages and
//! the directory index live in `LocalV6BlobStage`. Only the bounded canonical root
//! and one authenticated index reference enter a native Raft root command.
//!
//! These are local cryptographic/storage primitives. They do not manufacture a
//! consensus enrollment, a majority fsync receipt, an Actor or a request budget.
use super::{ClusterStateCodec, NONCE_BYTES, ReplicatedStateError, TAG_BYTES};
use crate::state_record_root::MAX_ROOT_BYTES;
use crate::state_record_root_v6::{ObjectDomain, OwnerDomain, RecordStateRootV6};
use crate::state_records::{BLOCK_BYTES, ObjectId, ObjectKind, ObjectRef};
use heptabao_raft_runtime::{
    LocalV6BlobError, LocalV6BlobStage, LocalV6ClosureReceipt, NativeV6CommitIntent,
    NativeV6PeerEnrollment, NativeV6PublishedRoot, RecordObjectKind, RecordObjectRef,
};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const OBJECT_MAGIC: &[u8; 5] = b"HBVO6";
const PAGE_MAGIC: &[u8; 5] = b"HBVP6";
const INDEX_MAGIC: &[u8; 5] = b"HBVD6";
const ROOT_MAGIC: &[u8; 5] = b"HBVR6";
const PAGE_BODY: &[u8; 8] = b"HBVDP001";
const INDEX_BODY: &[u8; 8] = b"HBVDI001";
const SEAL_HEADER: usize = 5 + NONCE_BYTES;
const SEAL_OVERHEAD: usize = SEAL_HEADER + TAG_BYTES;
const CIPHER_REF_BYTES: usize = 36;
const ROOT_HEADER: usize = 5 + CIPHER_REF_BYTES + NONCE_BYTES;
const MAX_CIPHER_CHUNK: usize = 256 * 1024;
const MAX_OBJECT_PLAIN: usize = BLOCK_BYTES + 25;
const MAX_OBJECT_CIPHER: usize = MAX_OBJECT_PLAIN + SEAL_OVERHEAD;
const MAX_PAGE_PLAIN: usize = MAX_CIPHER_CHUNK - SEAL_OVERHEAD;
const MAX_CLOSURE_OBJECTS: usize = 131_072;
const MAX_DIRECTORY_PAGES: usize = 128;
const PAGE_HEADER: usize = 8 + 2 + 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeV6CodecError {
    Envelope(ReplicatedStateError),
    Directory,
    TooLarge,
    Storage,
    Gate,
}
impl std::fmt::Display for NativeV6CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Envelope(error) => std::fmt::Display::fmt(error, f),
            Self::Directory => f.write_str("native V6 ciphertext directory is inconsistent"),
            Self::TooLarge => f.write_str("native V6 ciphertext closure exceeds its bound"),
            Self::Storage => f.write_str("native V6 ciphertext storage is unavailable or changed"),
            Self::Gate => f.write_str("original native V6 request gate is unavailable or expired"),
        }
    }
}
impl std::error::Error for NativeV6CodecError {}
impl From<ReplicatedStateError> for NativeV6CodecError {
    fn from(value: ReplicatedStateError) -> Self {
        Self::Envelope(value)
    }
}
pub(crate) type CodecResult<T> = Result<T, NativeV6CodecError>;

#[derive(Clone)]
struct ObjectMapping {
    reference: ObjectRef,
    parts: Vec<RecordObjectRef>,
}

/// Local, authenticated ciphertext mapping. Its private fields have no wire
/// constructor. Full typed graph validation belongs to the Service adapter.
pub(crate) struct NativeV6CipherClosure {
    root: RecordStateRootV6,
    root_bytes: Zeroizing<Vec<u8>>,
    root_digest: [u8; 32],
    enrollment_digest: [u8; 32],
    anchor: RecordObjectRef,
    objects: BTreeMap<(u16, ObjectId), ObjectMapping>,
    references: Vec<RecordObjectRef>,
    local: LocalV6ClosureReceipt,
}

/// A builder is deliberately not a typed closure certificate. It may stage
/// orphan ciphertext before a later graph or Actor check fails. Nothing here
/// changes either the local Service root or the consensus root.
pub(crate) struct NativeV6CipherBuilder<'a> {
    codec: &'a ClusterStateCodec,
    store: &'a LocalV6BlobStage,
    root: &'a RecordStateRootV6,
    root_bytes: Zeroizing<Vec<u8>>,
    root_digest: [u8; 32],
    enrollment_digest: [u8; 32],
    objects: BTreeMap<(u16, ObjectId), ObjectMapping>,
    references: BTreeMap<[u8; 32], RecordObjectRef>,
}

fn store_gate(
    gate: &mut impl FnMut() -> CodecResult<()>,
) -> impl FnMut() -> Result<(), LocalV6BlobError> + '_ {
    || gate().map_err(|_| LocalV6BlobError::CorruptOrChanged)
}

fn cipher_reference(bytes: &mut Vec<u8>, reference: &RecordObjectRef) -> CodecResult<()> {
    if reference.id == [0; 32]
        || reference.kind != RecordObjectKind::NativeV6CiphertextChunk
        || !(25..=MAX_CIPHER_CHUNK as u32).contains(&reference.encoded_bytes)
        || reference.record_count != 0
        || reference.payload_bytes != u64::from(reference.encoded_bytes)
    {
        return Err(NativeV6CodecError::Directory);
    }
    bytes.extend_from_slice(&reference.id);
    bytes.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    Ok(())
}

fn typed_reference(bytes: &mut Vec<u8>, reference: &ObjectRef) -> CodecResult<()> {
    if reference.id.bytes() == &[0; 32]
        || !(25..=MAX_OBJECT_PLAIN as u32).contains(&reference.encoded_bytes)
    {
        return Err(NativeV6CodecError::Directory);
    }
    bytes.extend_from_slice(reference.id.bytes());
    bytes.push(reference.kind as u8);
    bytes.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    bytes.extend_from_slice(&reference.record_count.to_be_bytes());
    bytes.extend_from_slice(&reference.payload_bytes.to_be_bytes());
    Ok(())
}

pub(crate) fn domain_index(root: &RecordStateRootV6, domain: &ObjectDomain) -> CodecResult<u16> {
    match domain {
        ObjectDomain::Owner(role) => OwnerDomain::ALL
            .iter()
            .position(|value| value == role)
            .map(|index| index as u16)
            .ok_or(NativeV6CodecError::Directory),
        ObjectDomain::Kv1 if root.kv1.reference.is_some() => Ok(5),
        ObjectDomain::Kv2(scope) => root
            .kv2
            .iter()
            .position(|graph| &graph.scope == scope)
            .map(|index| 6 + index as u16)
            .ok_or(NativeV6CodecError::Directory),
        _ => Err(NativeV6CodecError::Directory),
    }
}

fn indexed_domain(root: &RecordStateRootV6, index: u16) -> CodecResult<ObjectDomain> {
    match index {
        0..=4 => Ok(ObjectDomain::Owner(OwnerDomain::ALL[index as usize])),
        5 if root.kv1.reference.is_some() => Ok(ObjectDomain::Kv1),
        6.. => root
            .kv2
            .get(usize::from(index - 6))
            .map(|graph| ObjectDomain::Kv2(graph.scope.clone()))
            .ok_or(NativeV6CodecError::Directory),
        _ => Err(NativeV6CodecError::Directory),
    }
}

fn domain_bytes(bytes: &mut Vec<u8>, domain: &ObjectDomain) -> CodecResult<()> {
    fn field(out: &mut Vec<u8>, value: &str) -> CodecResult<()> {
        let length = u16::try_from(value.len()).map_err(|_| NativeV6CodecError::TooLarge)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        Ok(())
    }
    match domain {
        ObjectDomain::Owner(role) => {
            bytes.push(1);
            field(bytes, role.name())?;
        }
        ObjectDomain::Kv1 => bytes.push(2),
        ObjectDomain::Kv2(scope) => {
            scope
                .validate()
                .map_err(|_| NativeV6CodecError::Directory)?;
            bytes.push(3);
            field(bytes, &scope.namespace)?;
            field(bytes, &scope.mount)?;
            bytes.extend_from_slice(&scope.incarnation.to_be_bytes());
        }
    }
    Ok(())
}

fn validate_mapping(domain: &ObjectDomain, mapping: &ObjectMapping) -> CodecResult<()> {
    typed_reference(&mut Vec::new(), &mapping.reference)?;
    if matches!(domain, ObjectDomain::Owner(_))
        != (mapping.reference.kind == ObjectKind::OwnerChunk)
    {
        return Err(NativeV6CodecError::Directory);
    }
    let total = mapping.reference.encoded_bytes as usize + SEAL_OVERHEAD;
    let count = total.div_ceil(MAX_CIPHER_CHUNK);
    let width = total.div_ceil(count);
    if mapping.parts.len() != count || count > 2 {
        return Err(NativeV6CodecError::Directory);
    }
    for (index, reference) in mapping.parts.iter().enumerate() {
        cipher_reference(&mut Vec::new(), reference)?;
        let expected = width.min(total - index * width);
        if reference.encoded_bytes as usize != expected {
            return Err(NativeV6CodecError::Directory);
        }
    }
    Ok(())
}

fn include_reference(
    references: &mut BTreeMap<[u8; 32], RecordObjectRef>,
    reference: &RecordObjectRef,
) -> CodecResult<()> {
    cipher_reference(&mut Vec::new(), reference)?;
    if let Some(existing) = references.get(&reference.id) {
        if existing != reference {
            return Err(NativeV6CodecError::Directory);
        }
    } else {
        if references.len() >= MAX_CLOSURE_OBJECTS {
            return Err(NativeV6CodecError::TooLarge);
        }
        references.insert(reference.id, reference.clone());
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> CodecResult<&'a [u8]> {
        let end = self
            .at
            .checked_add(count)
            .ok_or(NativeV6CodecError::TooLarge)?;
        let value = self
            .bytes
            .get(self.at..end)
            .ok_or(NativeV6CodecError::Directory)?;
        self.at = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> CodecResult<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| NativeV6CodecError::Directory)
    }
    fn u16(&mut self) -> CodecResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> CodecResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> CodecResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn cipher(&mut self) -> CodecResult<RecordObjectRef> {
        let id = self.array()?;
        let encoded_bytes = self.u32()?;
        let reference = RecordObjectRef {
            id,
            kind: RecordObjectKind::NativeV6CiphertextChunk,
            encoded_bytes,
            record_count: 0,
            payload_bytes: u64::from(encoded_bytes),
        };
        cipher_reference(&mut Vec::new(), &reference)?;
        Ok(reference)
    }
    fn typed(&mut self) -> CodecResult<ObjectRef> {
        let id = ObjectId::from_bytes(self.array()?);
        let kind = match self.take(1)?[0] {
            1 => ObjectKind::Block,
            2 => ObjectKind::Value,
            3 => ObjectKind::Leaf,
            4 => ObjectKind::Branch,
            5 => ObjectKind::OwnerChunk,
            6 => ObjectKind::PackedLeaf,
            _ => return Err(NativeV6CodecError::Directory),
        };
        let reference = ObjectRef {
            id,
            kind,
            encoded_bytes: self.u32()?,
            record_count: self.u64()?,
            payload_bytes: self.u64()?,
        };
        typed_reference(&mut Vec::new(), &reference)?;
        Ok(reference)
    }
    fn finish(self) -> CodecResult<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(NativeV6CodecError::Directory)
        }
    }
}

impl ClusterStateCodec {
    /// The single cluster binding for the native Service/consensus/peer path.
    /// This is distinct from legacy observation and isolated-ingress profiles.
    pub(crate) fn native_v6_cluster_digest(&self) -> [u8; 32] {
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"heptabao.native-v6.replication.cluster.v1\0");
        hash.update(&(self.cluster_id.len() as u32).to_be_bytes());
        hash.update(self.cluster_id.as_bytes());
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.finish().as_ref());
        result
    }

    fn binding(
        &self,
        root: &RecordStateRootV6,
        enrollment: &NativeV6PeerEnrollment,
    ) -> CodecResult<()> {
        root.validate()
            .map_err(|_| ReplicatedStateError::InvalidState)?;
        if root.cluster_id != self.cluster_id
            || enrollment.cluster_digest() != self.native_v6_cluster_digest()
            || enrollment.epoch() != root.replay_epoch
        {
            return Err(ReplicatedStateError::InvalidCluster.into());
        }
        Ok(())
    }

    fn native_aad(&self, magic: &[u8; 5], epoch: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(5 + 4 + self.cluster_id.len() + 32 + 8);
        aad.extend_from_slice(magic);
        aad.extend_from_slice(&(self.cluster_id.len() as u32).to_be_bytes());
        aad.extend_from_slice(self.cluster_id.as_bytes());
        aad.extend_from_slice(&self.native_v6_cluster_digest());
        aad.extend_from_slice(&epoch.to_be_bytes());
        aad
    }

    fn object_aad(
        &self,
        epoch: u64,
        domain: &ObjectDomain,
        reference: &ObjectRef,
    ) -> CodecResult<Vec<u8>> {
        let mut aad = self.native_aad(OBJECT_MAGIC, epoch);
        domain_bytes(&mut aad, domain)?;
        typed_reference(&mut aad, reference)?;
        Ok(aad)
    }

    fn directory_aad(
        &self,
        magic: &[u8; 5],
        epoch: u64,
        root_digest: [u8; 32],
        enrollment_digest: [u8; 32],
        ordinal: u16,
    ) -> Vec<u8> {
        let mut aad = self.native_aad(magic, epoch);
        aad.extend_from_slice(&root_digest);
        aad.extend_from_slice(&enrollment_digest);
        aad.extend_from_slice(&ordinal.to_be_bytes());
        aad
    }

    fn seal_native_frame(&self, magic: &[u8; 5], aad: &[u8], bytes: &[u8]) -> CodecResult<Vec<u8>> {
        let mut nonce = [0u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        let mut ciphertext = Zeroizing::new(bytes.to_vec());
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut *ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(bytes.len() + SEAL_OVERHEAD);
        sealed.extend_from_slice(magic);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open_native_frame(
        &self,
        magic: &[u8; 5],
        aad: &[u8],
        sealed: &[u8],
        maximum: usize,
    ) -> CodecResult<Zeroizing<Vec<u8>>> {
        if sealed.len() < SEAL_OVERHEAD + 1
            || sealed.len() > maximum + SEAL_OVERHEAD
            || !sealed.starts_with(magic)
        {
            return Err(ReplicatedStateError::InvalidEnvelope.into());
        }
        let nonce = sealed[5..SEAL_HEADER]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let mut ciphertext = Zeroizing::new(sealed[SEAL_HEADER..].to_vec());
        let opened = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        Ok(Zeroizing::new(opened.to_vec()))
    }

    pub(crate) fn native_v6_builder<'a>(
        &'a self,
        root: &'a RecordStateRootV6,
        enrollment: &NativeV6PeerEnrollment,
        store: &'a LocalV6BlobStage,
    ) -> CodecResult<NativeV6CipherBuilder<'a>> {
        self.binding(root, enrollment)?;
        let root_bytes = root
            .encode()
            .map_err(|_| ReplicatedStateError::InvalidState)?;
        let root_digest = root
            .identity()
            .map_err(|_| ReplicatedStateError::InvalidState)?
            .digest();
        Ok(NativeV6CipherBuilder {
            codec: self,
            store,
            root,
            root_bytes,
            root_digest,
            enrollment_digest: enrollment.digest(),
            objects: BTreeMap::new(),
            references: BTreeMap::new(),
        })
    }

    /// Opens only the closure selected by an opaque, actually committed native
    /// root. No directory scan or caller-provided manifest is accepted. The
    /// caller must still perform the complete typed reader and recheck its fresh
    /// ReadIndex witness and original Actor before installation or delivery.
    pub(crate) fn open_native_v6_committed_closure(
        &self,
        enrollment: &NativeV6PeerEnrollment,
        published: &NativeV6PublishedRoot,
        store: &LocalV6BlobStage,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<NativeV6CipherClosure> {
        gate()?;
        let intent = published.intent();
        if enrollment.digest() != published.enrollment_digest()
            || enrollment.cluster_digest() != self.native_v6_cluster_digest()
            || intent.cluster_digest != enrollment.cluster_digest()
            || intent.epoch != enrollment.epoch()
        {
            return Err(ReplicatedStateError::InvalidCluster.into());
        }
        let actual = store
            .reopen_root_closure(published, &mut store_gate(gate))
            .map_err(|_| NativeV6CodecError::Storage)?;
        gate()?;
        let sealed = published.sealed_root();
        if !sealed.starts_with(ROOT_MAGIC)
            || !(ROOT_HEADER + TAG_BYTES + 1..=ROOT_HEADER + TAG_BYTES + MAX_ROOT_BYTES)
                .contains(&sealed.len())
        {
            return Err(ReplicatedStateError::InvalidEnvelope.into());
        }
        let mut decoder = Decoder {
            bytes: &sealed[5..5 + CIPHER_REF_BYTES],
            at: 0,
        };
        let anchor = decoder.cipher()?;
        decoder.finish()?;
        let mut aad = self.native_aad(ROOT_MAGIC, intent.epoch);
        aad.extend_from_slice(&enrollment.digest());
        aad.extend_from_slice(&intent.encode().map_err(|_| NativeV6CodecError::Directory)?);
        cipher_reference(&mut aad, &anchor)?;
        let mut frame = Vec::with_capacity(sealed.len() - CIPHER_REF_BYTES);
        frame.extend_from_slice(ROOT_MAGIC);
        frame.extend_from_slice(&sealed[5 + CIPHER_REF_BYTES..]);
        let root_bytes = self.open_native_frame(ROOT_MAGIC, &aad, &frame, MAX_ROOT_BYTES)?;
        gate()?;
        let root = RecordStateRootV6::decode(&root_bytes)
            .map_err(|_| ReplicatedStateError::InvalidState)?;
        self.binding(&root, enrollment)?;
        let root_digest = root
            .identity()
            .map_err(|_| ReplicatedStateError::InvalidState)?
            .digest();
        if root_digest != intent.proposed_root_digest {
            return Err(ReplicatedStateError::DigestMismatch.into());
        }
        let actual: BTreeMap<_, _> = actual
            .into_iter()
            .map(|reference| (reference.id, reference))
            .collect();
        let mut used = BTreeMap::new();
        let mut read_directory =
            |reference: &RecordObjectRef, magic, ordinal| -> CodecResult<Zeroizing<Vec<u8>>> {
                if actual.get(&reference.id) != Some(reference) {
                    return Err(NativeV6CodecError::Directory);
                }
                include_reference(&mut used, reference)?;
                gate()?;
                let sealed = store
                    .read_local(reference)
                    .map_err(|_| NativeV6CodecError::Storage)?;
                gate()?;
                let aad = self.directory_aad(
                    magic,
                    intent.epoch,
                    root_digest,
                    enrollment.digest(),
                    ordinal,
                );
                let plain = self.open_native_frame(magic, &aad, &sealed, MAX_PAGE_PLAIN)?;
                gate()?;
                Ok(plain)
            };
        let index = read_directory(&anchor, INDEX_MAGIC, 0)?;
        let mut index_decoder = Decoder {
            bytes: &index,
            at: 0,
        };
        if index_decoder.take(8)? != INDEX_BODY {
            return Err(NativeV6CodecError::Directory);
        }
        let object_count = index_decoder.u32()? as usize;
        let page_count = usize::from(index_decoder.u16()?);
        if object_count == 0
            || object_count > MAX_CLOSURE_OBJECTS
            || !(1..=MAX_DIRECTORY_PAGES).contains(&page_count)
        {
            return Err(NativeV6CodecError::TooLarge);
        }
        let mut pages = Vec::with_capacity(page_count);
        let mut page_ids = BTreeSet::new();
        for _ in 0..page_count {
            let page = index_decoder.cipher()?;
            if page.id == anchor.id || !page_ids.insert(page.id) {
                return Err(NativeV6CodecError::Directory);
            }
            pages.push(page);
        }
        index_decoder.finish()?;
        let mut objects = BTreeMap::new();
        let mut previous = None;
        let mut object_parts = Vec::new();
        for (ordinal, reference) in pages.iter().enumerate() {
            let page = read_directory(reference, PAGE_MAGIC, ordinal as u16)?;
            let mut decoder = Decoder {
                bytes: &page,
                at: 0,
            };
            if decoder.take(8)? != PAGE_BODY || usize::from(decoder.u16()?) != ordinal {
                return Err(NativeV6CodecError::Directory);
            }
            let entries = usize::from(decoder.u16()?);
            if entries == 0
                || objects
                    .len()
                    .checked_add(entries)
                    .is_none_or(|n| n > object_count)
            {
                return Err(NativeV6CodecError::Directory);
            }
            for _ in 0..entries {
                let domain = decoder.u16()?;
                let reference = decoder.typed()?;
                let count = decoder.take(1)?[0] as usize;
                if !(1..=2).contains(&count) {
                    return Err(NativeV6CodecError::Directory);
                }
                let mut parts = Vec::with_capacity(count);
                for _ in 0..count {
                    parts.push(decoder.cipher()?);
                }
                let key = (domain, reference.id);
                if previous.is_some_and(|prior| prior >= key) {
                    return Err(NativeV6CodecError::Directory);
                }
                previous = Some(key);
                let mapping = ObjectMapping { reference, parts };
                validate_mapping(&indexed_domain(&root, domain)?, &mapping)?;
                object_parts.extend(mapping.parts.iter().cloned());
                objects.insert(key, mapping);
            }
            decoder.finish()?;
        }
        drop(read_directory);
        if objects.len() != object_count {
            return Err(NativeV6CodecError::Directory);
        }
        for reference in &object_parts {
            if actual.get(&reference.id) != Some(reference) {
                return Err(NativeV6CodecError::Directory);
            }
            include_reference(&mut used, reference)?;
        }
        if used != actual {
            return Err(NativeV6CodecError::Directory);
        }
        gate()?;
        let references: Vec<_> = used.into_values().collect();
        // Reusing an existing immutable manifest also reopens its exact bytes
        // and completes the local fsync path. This remains a local receipt.
        let local = store
            .persist_local_closure(&references, &mut store_gate(gate))
            .map_err(|_| NativeV6CodecError::Storage)?;
        if local.manifest_sha256() != intent.closure_manifest_sha256
            || local.object_count() as u64 != intent.object_count
            || local.ciphertext_bytes() != intent.ciphertext_bytes
        {
            return Err(NativeV6CodecError::Directory);
        }
        gate()?;
        Ok(NativeV6CipherClosure {
            root,
            root_bytes,
            root_digest,
            enrollment_digest: enrollment.digest(),
            anchor,
            objects,
            references,
            local,
        })
    }
}

impl NativeV6CipherBuilder<'_> {
    pub(crate) fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub(crate) fn stage_object(
        &mut self,
        domain: &ObjectDomain,
        reference: &ObjectRef,
        plaintext: &[u8],
        reuse: Option<&NativeV6CipherClosure>,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<()> {
        gate()?;
        let index = domain_index(self.root, domain)?;
        if plaintext.len() != reference.encoded_bytes as usize
            || plaintext.len() < 25
            || plaintext.len() > MAX_OBJECT_PLAIN
        {
            return Err(NativeV6CodecError::Directory);
        }
        if let Some(existing) = self.objects.get(&(index, reference.id)) {
            if existing.reference != *reference {
                return Err(NativeV6CodecError::Directory);
            }
            let opened = self.read_mapping(domain, existing, gate)?;
            if opened.as_slice() != plaintext {
                return Err(ReplicatedStateError::DigestMismatch.into());
            }
            return gate();
        }
        if self.objects.len() >= MAX_CLOSURE_OBJECTS {
            return Err(NativeV6CodecError::TooLarge);
        }
        let prior = reuse
            .filter(|prior| {
                prior.root.cluster_id == self.root.cluster_id
                    && prior.root.replay_epoch == self.root.replay_epoch
            })
            .and_then(|prior| {
                domain_index(&prior.root, domain)
                    .ok()
                    .and_then(|index| prior.objects.get(&(index, reference.id)))
            });
        let mapping = if let Some(prior) = prior {
            if prior.reference != *reference {
                return Err(NativeV6CodecError::Directory);
            }
            let opened = self.read_mapping(domain, prior, gate)?;
            if opened.as_slice() != plaintext {
                return Err(ReplicatedStateError::DigestMismatch.into());
            }
            prior.clone()
        } else {
            let aad = self
                .codec
                .object_aad(self.root.replay_epoch, domain, reference)?;
            let sealed = self
                .codec
                .seal_native_frame(OBJECT_MAGIC, &aad, plaintext)?;
            gate()?;
            let width = sealed
                .len()
                .div_ceil(sealed.len().div_ceil(MAX_CIPHER_CHUNK));
            let mut parts = Vec::with_capacity(2);
            for part in sealed.chunks(width) {
                gate()?;
                let receipt = self
                    .store
                    .stage_local_checked(part, &mut store_gate(gate))
                    .map_err(|_| NativeV6CodecError::Storage)?;
                gate()?;
                parts.push(receipt.reference().clone());
            }
            ObjectMapping {
                reference: reference.clone(),
                parts,
            }
        };
        validate_mapping(domain, &mapping)?;
        for reference in &mapping.parts {
            include_reference(&mut self.references, reference)?;
        }
        self.objects.insert((index, reference.id), mapping);
        gate()
    }

    fn read_mapping(
        &self,
        domain: &ObjectDomain,
        mapping: &ObjectMapping,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<Zeroizing<Vec<u8>>> {
        read_mapping(
            self.codec,
            self.store,
            self.root.replay_epoch,
            domain,
            mapping,
            gate,
        )
    }

    fn stage_directory(
        &mut self,
        magic: &[u8; 5],
        ordinal: u16,
        plaintext: &[u8],
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<RecordObjectRef> {
        if plaintext.is_empty() || plaintext.len() > MAX_PAGE_PLAIN {
            return Err(NativeV6CodecError::TooLarge);
        }
        gate()?;
        let aad = self.codec.directory_aad(
            magic,
            self.root.replay_epoch,
            self.root_digest,
            self.enrollment_digest,
            ordinal,
        );
        let sealed = self.codec.seal_native_frame(magic, &aad, plaintext)?;
        gate()?;
        let reference = self
            .store
            .stage_local_checked(&sealed, &mut store_gate(gate))
            .map_err(|_| NativeV6CodecError::Storage)?
            .reference()
            .clone();
        gate()?;
        include_reference(&mut self.references, &reference)?;
        Ok(reference)
    }

    pub(crate) fn finish(
        mut self,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<NativeV6CipherClosure> {
        gate()?;
        if self.objects.is_empty() {
            return Err(NativeV6CodecError::Directory);
        }
        let mut pages = Vec::new();
        let mut page = Zeroizing::new(Vec::with_capacity(MAX_PAGE_PLAIN));
        page.extend_from_slice(PAGE_BODY);
        page.extend_from_slice(&[0u8; 4]);
        let mut count = 0u16;
        // Only bounded typed references are cloned; payload bytes never collect
        // into a closure-sized allocation or an application/Raft object list.
        let entries: Vec<_> = self
            .objects
            .iter()
            .map(|(key, mapping)| (*key, mapping.clone()))
            .collect();
        for ((domain, _), mapping) in entries {
            gate()?;
            let mut entry = Vec::with_capacity(128);
            entry.extend_from_slice(&domain.to_be_bytes());
            typed_reference(&mut entry, &mapping.reference)?;
            entry.push(mapping.parts.len() as u8);
            for reference in &mapping.parts {
                cipher_reference(&mut entry, reference)?;
            }
            if page.len() + entry.len() > MAX_PAGE_PLAIN {
                if pages.len() >= MAX_DIRECTORY_PAGES {
                    return Err(NativeV6CodecError::TooLarge);
                }
                page[8..10].copy_from_slice(&(pages.len() as u16).to_be_bytes());
                page[10..12].copy_from_slice(&count.to_be_bytes());
                let reference =
                    self.stage_directory(PAGE_MAGIC, pages.len() as u16, &page, gate)?;
                pages.push(reference);
                page.clear();
                page.extend_from_slice(PAGE_BODY);
                page.extend_from_slice(&[0u8; 4]);
                count = 0;
            }
            page.extend_from_slice(&entry);
            count = count.checked_add(1).ok_or(NativeV6CodecError::TooLarge)?;
        }
        if count == 0 || page.len() < PAGE_HEADER || pages.len() >= MAX_DIRECTORY_PAGES {
            return Err(NativeV6CodecError::Directory);
        }
        page[8..10].copy_from_slice(&(pages.len() as u16).to_be_bytes());
        page[10..12].copy_from_slice(&count.to_be_bytes());
        let reference = self.stage_directory(PAGE_MAGIC, pages.len() as u16, &page, gate)?;
        pages.push(reference);
        let mut index = Zeroizing::new(Vec::with_capacity(14 + CIPHER_REF_BYTES * pages.len()));
        index.extend_from_slice(INDEX_BODY);
        index.extend_from_slice(&(self.objects.len() as u32).to_be_bytes());
        index.extend_from_slice(&(pages.len() as u16).to_be_bytes());
        for reference in &pages {
            cipher_reference(&mut index, reference)?;
        }
        let anchor = self.stage_directory(INDEX_MAGIC, 0, &index, gate)?;
        let references: Vec<_> = self.references.into_values().collect();
        let local = self
            .store
            .persist_local_closure(&references, &mut store_gate(gate))
            .map_err(|_| NativeV6CodecError::Storage)?;
        gate()?;
        Ok(NativeV6CipherClosure {
            root: self.root.clone(),
            root_bytes: self.root_bytes,
            root_digest: self.root_digest,
            enrollment_digest: self.enrollment_digest,
            anchor,
            objects: self.objects,
            references,
            local,
        })
    }
}

fn read_mapping(
    codec: &ClusterStateCodec,
    store: &LocalV6BlobStage,
    epoch: u64,
    domain: &ObjectDomain,
    mapping: &ObjectMapping,
    gate: &mut impl FnMut() -> CodecResult<()>,
) -> CodecResult<Zeroizing<Vec<u8>>> {
    gate()?;
    validate_mapping(domain, mapping)?;
    let expected = mapping.reference.encoded_bytes as usize + SEAL_OVERHEAD;
    if expected > MAX_OBJECT_CIPHER {
        return Err(NativeV6CodecError::TooLarge);
    }
    let mut sealed = Vec::with_capacity(expected);
    for reference in &mapping.parts {
        gate()?;
        let part = store
            .read_local(reference)
            .map_err(|_| NativeV6CodecError::Storage)?;
        gate()?;
        if sealed
            .len()
            .checked_add(part.len())
            .is_none_or(|n| n > expected)
        {
            return Err(NativeV6CodecError::Directory);
        }
        sealed.extend_from_slice(&part);
    }
    if sealed.len() != expected {
        return Err(NativeV6CodecError::Directory);
    }
    let aad = codec.object_aad(epoch, domain, &mapping.reference)?;
    let plain = codec.open_native_frame(OBJECT_MAGIC, &aad, &sealed, MAX_OBJECT_PLAIN)?;
    if plain.len() != mapping.reference.encoded_bytes as usize {
        return Err(NativeV6CodecError::Directory);
    }
    gate()?;
    Ok(plain)
}

impl NativeV6CipherClosure {
    pub(crate) fn root(&self) -> &RecordStateRootV6 {
        &self.root
    }
    pub(crate) fn root_bytes(&self) -> &[u8] {
        &self.root_bytes
    }
    pub(crate) fn root_digest(&self) -> [u8; 32] {
        self.root_digest
    }
    pub(crate) fn object_count(&self) -> usize {
        self.objects.len()
    }
    pub(crate) fn references(&self) -> &[RecordObjectRef] {
        &self.references
    }
    pub(crate) fn local_closure(&self) -> LocalV6ClosureReceipt {
        self.local
    }

    pub(crate) fn visit_objects(
        &self,
        codec: &ClusterStateCodec,
        store: &LocalV6BlobStage,
        gate: &mut impl FnMut() -> CodecResult<()>,
        visit: &mut impl FnMut(&ObjectDomain, &ObjectRef, &[u8]) -> CodecResult<()>,
    ) -> CodecResult<()> {
        for ((index, _), mapping) in &self.objects {
            gate()?;
            let domain = indexed_domain(&self.root, *index)?;
            let bytes = self.read_object(codec, store, &domain, &mapping.reference, gate)?;
            gate()?;
            visit(&domain, &mapping.reference, &bytes)?;
            gate()?;
        }
        gate()
    }

    pub(crate) fn read_object(
        &self,
        codec: &ClusterStateCodec,
        store: &LocalV6BlobStage,
        domain: &ObjectDomain,
        expected: &ObjectRef,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<Zeroizing<Vec<u8>>> {
        gate()?;
        if self.root.cluster_id != codec.cluster_id {
            return Err(ReplicatedStateError::InvalidCluster.into());
        }
        let index = domain_index(&self.root, domain)?;
        let mapping = self
            .objects
            .get(&(index, expected.id))
            .ok_or(NativeV6CodecError::Directory)?;
        if mapping.reference != *expected {
            return Err(ReplicatedStateError::DigestMismatch.into());
        }
        read_mapping(codec, store, self.root.replay_epoch, domain, mapping, gate)
    }

    pub(crate) fn seal_root(
        &self,
        codec: &ClusterStateCodec,
        enrollment: &NativeV6PeerEnrollment,
        intent: &NativeV6CommitIntent,
        gate: &mut impl FnMut() -> CodecResult<()>,
    ) -> CodecResult<Vec<u8>> {
        gate()?;
        codec.binding(&self.root, enrollment)?;
        if self.enrollment_digest != enrollment.digest()
            || intent.cluster_digest != enrollment.cluster_digest()
            || intent.epoch != self.root.replay_epoch
            || intent.proposed_root_digest != self.root_digest
            || intent.closure_manifest_sha256 != self.local.manifest_sha256()
            || intent.object_count != self.local.object_count() as u64
            || intent.ciphertext_bytes != self.local.ciphertext_bytes()
        {
            return Err(NativeV6CodecError::Directory);
        }
        let mut aad = codec.native_aad(ROOT_MAGIC, intent.epoch);
        aad.extend_from_slice(&enrollment.digest());
        aad.extend_from_slice(&intent.encode().map_err(|_| NativeV6CodecError::Directory)?);
        cipher_reference(&mut aad, &self.anchor)?;
        let frame = codec.seal_native_frame(ROOT_MAGIC, &aad, &self.root_bytes)?;
        gate()?;
        let mut result = Vec::with_capacity(frame.len() + CIPHER_REF_BYTES);
        result.extend_from_slice(ROOT_MAGIC);
        cipher_reference(&mut result, &self.anchor)?;
        result.extend_from_slice(&frame[5..]);
        if result.len() > MAX_ROOT_BYTES + 256 {
            return Err(NativeV6CodecError::TooLarge);
        }
        Ok(result)
    }
}
