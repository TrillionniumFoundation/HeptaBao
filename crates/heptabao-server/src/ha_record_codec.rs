//! HBSM5 publishes the same small canonical root as local storage. Immutable
//! objects authenticate their typed references and dependencies independently.
use super::*;
use crate::state_record_root::{MAX_ROOT_BYTES, RecordStateRoot, StateIdentity};
use crate::state_records::{AddressKey, ObjectId, ObjectKind, ObjectRef, StagedObject};
use heptabao_raft_runtime::{
    RecordObjectKind, RecordObjectRef, RecordRootBase, SealedRecordObject,
};

pub(super) const ROOT_MAGIC: &[u8; 5] = b"HBSM5";
const OBJECT_MAGIC: &[u8; 5] = b"HBRO5";
const BASE_BYTES: usize = 33;
pub(super) const ROOT_HEADER_BYTES: usize = ROOT_MAGIC.len() + BASE_BYTES + NONCE_BYTES;
const OBJECT_HEADER_BYTES: usize = OBJECT_MAGIC.len() + NONCE_BYTES;

pub(crate) struct CommittedRecordRoot {
    pub(crate) base: RecordRootBase,
    pub(crate) root: RecordStateRoot,
    pub(crate) bytes: Zeroizing<Vec<u8>>,
}

pub(crate) fn runtime_reference(reference: &ObjectRef) -> RecordObjectRef {
    RecordObjectRef {
        id: *reference.id.bytes(),
        kind: match reference.kind {
            ObjectKind::Block => RecordObjectKind::Block,
            ObjectKind::Value => RecordObjectKind::Value,
            ObjectKind::Leaf => RecordObjectKind::Leaf,
            ObjectKind::Branch => RecordObjectKind::Branch,
            ObjectKind::OwnerChunk => RecordObjectKind::OwnerChunk,
            ObjectKind::PackedLeaf => RecordObjectKind::PackedLeaf,
        },
        encoded_bytes: reference.encoded_bytes,
        record_count: reference.record_count,
        payload_bytes: reference.payload_bytes,
    }
}

pub(crate) fn core_reference(reference: &RecordObjectRef) -> ObjectRef {
    ObjectRef {
        id: ObjectId::from_bytes(reference.id),
        kind: match reference.kind {
            RecordObjectKind::Block => ObjectKind::Block,
            RecordObjectKind::Value => ObjectKind::Value,
            RecordObjectKind::Leaf => ObjectKind::Leaf,
            RecordObjectKind::Branch => ObjectKind::Branch,
            RecordObjectKind::OwnerChunk => ObjectKind::OwnerChunk,
            RecordObjectKind::PackedLeaf => ObjectKind::PackedLeaf,
        },
        encoded_bytes: reference.encoded_bytes,
        record_count: reference.record_count,
        payload_bytes: reference.payload_bytes,
    }
}

fn base_bytes(base: &RecordRootBase) -> [u8; BASE_BYTES] {
    let mut bytes = [0_u8; BASE_BYTES];
    match base {
        RecordRootBase::Empty => {}
        RecordRootBase::Legacy(digest) => {
            bytes[0] = 1;
            bytes[1..].copy_from_slice(digest);
        }
        RecordRootBase::RecordsV5(digest) => {
            bytes[0] = 5;
            bytes[1..].copy_from_slice(digest);
        }
    }
    bytes
}

fn parse_base(bytes: &[u8]) -> Result<RecordRootBase, ReplicatedStateError> {
    if bytes.len() != BASE_BYTES {
        return Err(ReplicatedStateError::InvalidEnvelope);
    }
    let digest: [u8; 32] = bytes[1..]
        .try_into()
        .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
    match bytes[0] {
        0 if digest == [0; 32] => Ok(RecordRootBase::Empty),
        1 if digest != [0; 32] => Ok(RecordRootBase::Legacy(digest)),
        5 if digest != [0; 32] => Ok(RecordRootBase::RecordsV5(digest)),
        _ => Err(ReplicatedStateError::InvalidEnvelope),
    }
}

fn append_reference(aad: &mut Vec<u8>, reference: &RecordObjectRef) {
    aad.extend_from_slice(&reference.id);
    aad.push(match reference.kind {
        RecordObjectKind::Block => 1,
        RecordObjectKind::Value => 2,
        RecordObjectKind::Leaf => 3,
        RecordObjectKind::Branch => 4,
        RecordObjectKind::OwnerChunk => 5,
        RecordObjectKind::PackedLeaf => 6,
    });
    aad.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    aad.extend_from_slice(&reference.record_count.to_be_bytes());
    aad.extend_from_slice(&reference.payload_bytes.to_be_bytes());
}

impl ClusterStateCodec {
    fn record_aad_prefix(&self, magic: &[u8; 5]) -> Result<Vec<u8>, ReplicatedStateError> {
        let length = u16::try_from(self.cluster_id.len())
            .map_err(|_| ReplicatedStateError::InvalidCluster)?;
        let mut aad = magic.to_vec();
        aad.extend_from_slice(&length.to_be_bytes());
        aad.extend_from_slice(self.cluster_id.as_bytes());
        Ok(aad)
    }

    fn record_root_aad(
        &self,
        operation: &str,
        base: &RecordRootBase,
        identity: [u8; 32],
    ) -> Result<Vec<u8>, ReplicatedStateError> {
        validate_operation_id(operation)?;
        let mut aad = self.record_aad_prefix(ROOT_MAGIC)?;
        aad.extend_from_slice(&(operation.len() as u16).to_be_bytes());
        aad.extend_from_slice(operation.as_bytes());
        aad.extend_from_slice(&base_bytes(base));
        aad.extend_from_slice(&identity);
        Ok(aad)
    }

    pub(crate) fn seal_record_root(
        &self,
        operation: &str,
        base: &RecordRootBase,
        root: &RecordStateRoot,
    ) -> Result<ReplicatedStateProposal, ReplicatedStateError> {
        if root.cluster_id != self.cluster_id {
            return Err(ReplicatedStateError::InvalidCluster);
        }
        let encoded_base = base_bytes(base);
        parse_base(&encoded_base)?;
        let mut ciphertext = root
            .encode()
            .map_err(|_| ReplicatedStateError::InvalidState)?;
        let identity = root
            .identity()
            .map_err(|_| ReplicatedStateError::InvalidState)?
            .digest();
        let aad = self.record_root_aad(operation, base, identity)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut *ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(ROOT_HEADER_BYTES + ciphertext.len());
        sealed.extend_from_slice(ROOT_MAGIC);
        sealed.extend_from_slice(&encoded_base);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        ReplicatedStateProposal::new(operation.to_owned(), identity, sealed)
    }

    pub(crate) fn open_record_root(
        &self,
        operation: &str,
        identity: [u8; 32],
        sealed: &[u8],
    ) -> Result<CommittedRecordRoot, ReplicatedStateError> {
        if !sealed.starts_with(ROOT_MAGIC)
            || !(ROOT_HEADER_BYTES + TAG_BYTES + 1..=ROOT_HEADER_BYTES + TAG_BYTES + MAX_ROOT_BYTES)
                .contains(&sealed.len())
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let base_end = ROOT_MAGIC.len() + BASE_BYTES;
        let base = parse_base(&sealed[ROOT_MAGIC.len()..base_end])?;
        let nonce = sealed[base_end..ROOT_HEADER_BYTES]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let aad = self.record_root_aad(operation, &base, identity)?;
        let mut ciphertext = Zeroizing::new(sealed[ROOT_HEADER_BYTES..].to_vec());
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let root =
            RecordStateRoot::decode(plaintext).map_err(|_| ReplicatedStateError::InvalidState)?;
        if root.cluster_id != self.cluster_id {
            return Err(ReplicatedStateError::InvalidCluster);
        }
        if root
            .identity()
            .map_err(|_| ReplicatedStateError::InvalidState)?
            != StateIdentity::RecordsV5(identity)
        {
            return Err(ReplicatedStateError::DigestMismatch);
        }
        Ok(CommittedRecordRoot {
            base,
            root,
            bytes: Zeroizing::new(plaintext.to_vec()),
        })
    }

    fn record_object_aad(
        &self,
        reference: &RecordObjectRef,
        children: &[RecordObjectRef],
    ) -> Result<Vec<u8>, ReplicatedStateError> {
        if children.len() > 256
            || reference.encoded_bytes == 0
            || reference.encoded_bytes as usize > 1024 * 1024
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let mut aad = self.record_aad_prefix(OBJECT_MAGIC)?;
        append_reference(&mut aad, reference);
        aad.extend_from_slice(&(children.len() as u16).to_be_bytes());
        for child in children {
            append_reference(&mut aad, child);
        }
        Ok(aad)
    }

    pub(crate) fn seal_record_object(
        &self,
        key: &AddressKey,
        object: &StagedObject,
    ) -> Result<SealedRecordObject, ReplicatedStateError> {
        object
            .reference()
            .verify(key, object.bytes())
            .map_err(|_| ReplicatedStateError::InvalidState)?;
        let reference = runtime_reference(object.reference());
        let children = object
            .children()
            .iter()
            .map(runtime_reference)
            .collect::<Vec<_>>();
        let aad = self.record_object_aad(&reference, &children)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ReplicatedStateError::RandomnessUnavailable)?;
        let mut ciphertext = Zeroizing::new(object.bytes().to_vec());
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut *ciphertext,
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        let mut sealed = Vec::with_capacity(OBJECT_HEADER_BYTES + ciphertext.len());
        sealed.extend_from_slice(OBJECT_MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        SealedRecordObject::new(reference, children, sealed)
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)
    }

    pub(crate) fn open_record_object(
        &self,
        key: &AddressKey,
        expected: &ObjectRef,
        object: &SealedRecordObject,
    ) -> Result<Zeroizing<Vec<u8>>, ReplicatedStateError> {
        if core_reference(object.reference()) != *expected {
            return Err(ReplicatedStateError::DigestMismatch);
        }
        let sealed = object.sealed();
        if !sealed.starts_with(OBJECT_MAGIC)
            || sealed.len() != OBJECT_HEADER_BYTES + expected.encoded_bytes as usize + TAG_BYTES
        {
            return Err(ReplicatedStateError::InvalidEnvelope);
        }
        let nonce = sealed[OBJECT_MAGIC.len()..OBJECT_HEADER_BYTES]
            .try_into()
            .map_err(|_| ReplicatedStateError::InvalidEnvelope)?;
        let aad = self.record_object_aad(object.reference(), object.children())?;
        let mut ciphertext = Zeroizing::new(sealed[OBJECT_HEADER_BYTES..].to_vec());
        let plaintext = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| ReplicatedStateError::AuthenticationFailed)?;
        expected
            .verify(key, plaintext)
            .map_err(|_| ReplicatedStateError::DigestMismatch)?;
        Ok(Zeroizing::new(plaintext.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_record_root::{OWNER_NAMES, OpaqueOwnerRef, digest_owner};
    use crate::state_records::Kv1Root;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn fixture() -> Result<(RecordStateRoot, Vec<std::sync::Arc<StagedObject>>)> {
        let address_key = AddressKey::from_bytes([7; 32]);
        let mut objects = Vec::new();
        let mut owners = Vec::new();
        for name in OWNER_NAMES {
            let payload = format!("{{\"owner\":\"{name}\",\"synthetic\":true}}");
            let object = StagedObject::owner_chunk(&address_key, payload.as_bytes())?;
            owners.push(OpaqueOwnerRef {
                name: name.into(),
                total_bytes: payload.len() as u64,
                chunks: vec![object.reference().clone()],
                digest: digest_owner(&address_key, name, payload.as_bytes())
                    .map_err(|_| "owner digest")?,
            });
            objects.push(object);
        }
        let owners = owners.try_into().map_err(|_| "owner count")?;
        let root = RecordStateRoot::new(
            36,
            "cluster-records".into(),
            0,
            owners,
            Kv1Root {
                reference: None,
                height: 0,
            },
            [7; 32],
        )
        .map_err(|_| "root")?;
        Ok((root, objects))
    }

    #[test]
    fn record_root_authenticates_base_kind_operation_cluster_and_canonical_identity() -> Result {
        let codec = ClusterStateCodec::new("cluster-records", [3; 32])?;
        let (root, _) = fixture()?;
        for base in [
            RecordRootBase::Empty,
            RecordRootBase::Legacy([1; 32]),
            RecordRootBase::RecordsV5([1; 32]),
        ] {
            let proposal = codec.seal_record_root("root-op", &base, &root)?;
            let decoded =
                codec.open_record_root("root-op", proposal.digest(), proposal.sealed())?;
            assert_eq!(decoded.base, base);
            assert_eq!(
                decoded.root.identity().map_err(|_| "identity")?,
                root.identity().map_err(|_| "identity")?
            );
            assert_eq!(
                decoded.bytes.as_slice(),
                root.encode().map_err(|_| "encode")?.as_slice()
            );
            assert!(
                codec
                    .open_record_root("wrong-op", proposal.digest(), proposal.sealed())
                    .is_err()
            );
            assert!(
                codec
                    .open_record_root("root-op", [9; 32], proposal.sealed())
                    .is_err()
            );
            let foreign = ClusterStateCodec::new("other-cluster", [3; 32])?;
            assert!(
                foreign
                    .open_record_root("root-op", proposal.digest(), proposal.sealed())
                    .is_err()
            );
            let mut altered = proposal.sealed().to_vec();
            altered[ROOT_HEADER_BYTES] ^= 1;
            assert!(
                codec
                    .open_record_root("root-op", proposal.digest(), &altered)
                    .is_err()
            );
            let mut altered = proposal.sealed().to_vec();
            altered[ROOT_MAGIC.len()] = if matches!(base, RecordRootBase::Legacy(_)) {
                5
            } else {
                1
            };
            assert!(
                codec
                    .open_record_root("root-op", proposal.digest(), &altered)
                    .is_err()
            );
            assert!(matches!(
                codec.open_committed_descriptor("root-op", proposal.digest(), proposal.sealed())?,
                CommittedStateDescriptor::RecordsV5(_)
            ));
        }
        Ok(())
    }

    #[test]
    fn record_object_binds_typed_metadata_dependencies_address_key_and_cluster() -> Result {
        let codec = ClusterStateCodec::new("cluster-records", [3; 32])?;
        let (root, objects) = fixture()?;
        let object = &objects[0];
        let key = root.address_key();
        let sealed = codec.seal_record_object(&key, object)?;
        assert_eq!(
            codec
                .open_record_object(&key, object.reference(), &sealed)?
                .as_slice(),
            object.bytes()
        );
        let other = codec.seal_record_object(&key, object)?;
        assert_eq!(sealed.reference(), other.reference());
        assert_ne!(
            sealed.sealed(),
            other.sealed(),
            "random AEAD nonces do not become object identity"
        );
        assert!(
            codec
                .open_record_object(
                    &AddressKey::from_bytes([8; 32]),
                    object.reference(),
                    &sealed
                )
                .is_err()
        );
        let foreign = ClusterStateCodec::new("other-cluster", [3; 32])?;
        assert!(
            foreign
                .open_record_object(&key, object.reference(), &sealed)
                .is_err()
        );
        let mut reference = sealed.reference().clone();
        reference.id[0] ^= 1;
        let altered = SealedRecordObject::new(
            reference.clone(),
            sealed.children().to_vec(),
            sealed.sealed().to_vec(),
        )?;
        assert!(
            codec
                .open_record_object(&key, &core_reference(&reference), &altered)
                .is_err()
        );
        // Keep the descriptor structurally valid, then alter a child address.
        // This reaches AEAD verification instead of only constructor validation.
        let index = crate::state_records::Kv1Index::empty(std::sync::Arc::clone(&key));
        let external_value = format!("\"{}\"", "x".repeat(1024));
        let edit = index.edit(
            crate::state_records::Kv1Key::new("root", "secret/", 1, "key")?,
            Some(external_value.as_bytes()),
        )?;
        let parent = edit
            .objects
            .iter()
            .find(|object| !object.children().is_empty())
            .ok_or("parent")?;
        let sealed_parent = codec.seal_record_object(&key, parent)?;
        let mut children = sealed_parent.children().to_vec();
        children[0].id[0] ^= 1;
        let altered = SealedRecordObject::new(
            sealed_parent.reference().clone(),
            children,
            sealed_parent.sealed().to_vec(),
        )?;
        assert!(
            codec
                .open_record_object(&key, parent.reference(), &altered)
                .is_err()
        );
        let mut damaged = sealed.sealed().to_vec();
        damaged[OBJECT_HEADER_BYTES] ^= 1;
        let altered = SealedRecordObject::new(
            sealed.reference().clone(),
            sealed.children().to_vec(),
            damaged,
        )?;
        assert!(
            codec
                .open_record_object(&key, object.reference(), &altered)
                .is_err()
        );
        assert!(
            codec
                .open_record_object(&key, objects[1].reference(), &sealed)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn record_kind_aad_keeps_existing_tags_and_adds_packed_leaf_six() -> Result {
        for (kind, tag) in [
            (RecordObjectKind::Block, 1),
            (RecordObjectKind::Value, 2),
            (RecordObjectKind::Leaf, 3),
            (RecordObjectKind::Branch, 4),
            (RecordObjectKind::OwnerChunk, 5),
            (RecordObjectKind::PackedLeaf, 6),
        ] {
            let reference = RecordObjectRef {
                id: [11; 32],
                kind,
                encoded_bytes: 123,
                record_count: 2,
                payload_bytes: 17,
            };
            assert_eq!(runtime_reference(&core_reference(&reference)), reference);
            let mut aad = Vec::new();
            append_reference(&mut aad, &reference);
            let mut expected = vec![11; 32];
            expected.push(tag);
            expected.extend_from_slice(&123_u32.to_be_bytes());
            expected.extend_from_slice(&2_u64.to_be_bytes());
            expected.extend_from_slice(&17_u64.to_be_bytes());
            assert_eq!(aad, expected);
        }
        Ok(())
    }

    #[test]
    fn packed_leaf_ciphertext_authenticates_inline_aggregate_and_external_value_edge() -> Result {
        let key = AddressKey::from_bytes([17; 32]);
        let codec = ClusterStateCodec::new("packed-records", [18; 32])?;
        let index = crate::state_records::Kv1Index::empty(std::sync::Arc::clone(&key));
        let first = index.edit(
            crate::state_records::Kv1Key::new("root", "secret/", 1, "a")?,
            Some(b"{\"ok\":true}"),
        )?;
        let inline = first
            .objects
            .iter()
            .find(|object| object.reference().kind == ObjectKind::PackedLeaf)
            .ok_or("packed inline page")?;
        let sealed = codec.seal_record_object(&key, inline)?;
        assert_eq!(
            codec
                .open_record_object(&key, inline.reference(), &sealed)?
                .as_slice(),
            inline.bytes()
        );
        let mut changed = sealed.reference().clone();
        changed.record_count += 1;
        let forged = SealedRecordObject::new(changed.clone(), vec![], sealed.sealed().to_vec())?;
        assert!(
            codec
                .open_record_object(&key, &core_reference(&changed), &forged)
                .is_err()
        );
        let value = format!("\"{}\"", "x".repeat(1024));
        let second = first.next.edit(
            crate::state_records::Kv1Key::new("root", "secret/", 1, "b")?,
            Some(value.as_bytes()),
        )?;
        let mixed = second
            .objects
            .iter()
            .find(|object| object.reference().kind == ObjectKind::PackedLeaf)
            .ok_or("packed mixed page")?;
        let sealed = codec.seal_record_object(&key, mixed)?;
        assert_eq!(sealed.children().len(), 1);
        assert_eq!(
            codec
                .open_record_object(&key, mixed.reference(), &sealed)?
                .as_slice(),
            mixed.bytes()
        );
        let mut children = sealed.children().to_vec();
        children[0].id[0] ^= 1;
        let forged = SealedRecordObject::new(
            sealed.reference().clone(),
            children,
            sealed.sealed().to_vec(),
        )?;
        assert!(
            codec
                .open_record_object(&key, mixed.reference(), &forged)
                .is_err()
        );
        let mut damaged = sealed.sealed().to_vec();
        damaged[OBJECT_HEADER_BYTES] ^= 1;
        let forged = SealedRecordObject::new(
            sealed.reference().clone(),
            sealed.children().to_vec(),
            damaged,
        )?;
        assert!(
            codec
                .open_record_object(&key, mixed.reference(), &forged)
                .is_err()
        );
        Ok(())
    }
}
