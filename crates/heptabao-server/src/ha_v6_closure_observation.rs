//! Read-only authenticated V6 object-closure observation for a future Raft
//! publication. Not a consensus witness, writer capability or migration grant.
use crate::ha_v6_root_preflight::{V6RootAdmissionError, V6RootProposal};
use crate::state_record_root_v6::{MountScope, ObjectDomain, RecordStateRootV6};
use crate::v6_read_validation::{EncodedDomain, EncodedObject, ReadContext, inspect_v6_records};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Verified against the real V6 typed reader, but **not** against a Raft quorum.
/// Fields are intentionally not serialized or exposed as a wire receipt.
pub(crate) struct V6ClosureObservation {
    cluster: [u8; 32],
    epoch: u64,
    root_digest: [u8; 32],
    closure_digest: [u8; 32],
    objects_checked: usize,
}

impl V6ClosureObservation {
    pub(crate) fn cluster(&self) -> [u8; 32] {
        self.cluster
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }
    pub(crate) fn root_digest(&self) -> [u8; 32] {
        self.root_digest
    }
    pub(crate) fn closure_digest(&self) -> [u8; 32] {
        self.closure_digest
    }
    pub(crate) fn objects_checked(&self) -> usize {
        self.objects_checked
    }
}

/// Distinct from authorizing a write: validates actual canonical root bytes,
/// role/mount-scoped object graph, cryptographic references, and protected owners.
/// The digest is keyed to this root and ordered by (domain, object id).
pub(crate) fn inspect_prepared_v6_closure(
    canonical_root: &[u8],
    context: ReadContext<'_>,
    encoded_objects: &[EncodedObject<'_>],
) -> Result<V6ClosureObservation, V6RootAdmissionError> {
    let root = RecordStateRootV6::decode(canonical_root)
        .map_err(|_| V6RootAdmissionError::InvalidClosure)?;
    let receipt = inspect_v6_records(canonical_root, context, encoded_objects)
        .map_err(|_| V6RootAdmissionError::InvalidClosure)?;
    if receipt.objects_read == 0
        || encoded_objects.is_empty()
        || receipt.production_writer_admitted
        || receipt.replacement_authority
    {
        return Err(V6RootAdmissionError::InvalidClosure);
    }

    // The V6 root's address material is already protected by the original
    // barrier; never emit these object MACs to public logs or API responses.
    let address = root
        .key(b"state-v6/raft-scoped-closure/v1")
        .map_err(|_| V6RootAdmissionError::InvalidClosure)?;
    let mut rows = BTreeMap::<(ObjectDomain, [u8; 32]), [u8; 32]>::new();
    for object in encoded_objects {
        let (domain, mut framed) = match object.domain {
            EncodedDomain::Owner(role) => {
                let mut v = vec![1];
                append_len_prefixed(&mut v, role.name().as_bytes())?;
                (ObjectDomain::Owner(role), v)
            }
            EncodedDomain::Kv1 => (ObjectDomain::Kv1, vec![2]),
            EncodedDomain::Kv2(scope) => {
                let mut v = vec![3];
                append_len_prefixed(&mut v, scope.namespace.as_bytes())?;
                append_len_prefixed(&mut v, scope.mount.as_bytes())?;
                v.extend_from_slice(&scope.incarnation.to_be_bytes());
                (
                    ObjectDomain::Kv2(MountScope {
                        namespace: scope.namespace.to_owned(),
                        mount: scope.mount.to_owned(),
                        incarnation: scope.incarnation,
                    }),
                    v,
                )
            }
        };
        framed.extend_from_slice(&object.id);
        // Never clone secret object bytes into a second allocation. The
        // root-derived MAC binds their length and full SHA-256 digest.
        let length =
            u32::try_from(object.bytes.len()).map_err(|_| V6RootAdmissionError::InvalidClosure)?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&Sha256::digest(object.bytes));
        let mac = address
            .digest(b"heptabao/v6/raft/scoped-object/v1", &framed)
            .map_err(|_| V6RootAdmissionError::InvalidClosure)?;
        if rows.insert((domain, object.id), mac).is_some() {
            return Err(V6RootAdmissionError::InvalidClosure);
        }
    }

    let root_digest = root
        .identity()
        .map_err(|_| V6RootAdmissionError::InvalidClosure)?
        .digest();
    let mut closure = Sha256::new();
    closure.update(b"heptabao/v6/raft/scoped-closure/v1");
    closure.update(root_digest);
    closure.update(
        u64::try_from(rows.len())
            .map_err(|_| V6RootAdmissionError::InvalidClosure)?
            .to_be_bytes(),
    );
    // Root-derived MACs incorporate domain, id, exact canonical ciphertext/
    // plaintext record encoding and size. Sorting prevents order-based aliases.
    for ((domain, id), mac) in rows {
        let mut label = match domain {
            ObjectDomain::Owner(role) => {
                let mut v = vec![1];
                append_len_prefixed(&mut v, role.name().as_bytes())?;
                v
            }
            ObjectDomain::Kv1 => vec![2],
            ObjectDomain::Kv2(scope) => {
                let mut v = vec![3];
                append_len_prefixed(&mut v, scope.namespace.as_bytes())?;
                append_len_prefixed(&mut v, scope.mount.as_bytes())?;
                v.extend_from_slice(&scope.incarnation.to_be_bytes());
                v
            }
        };
        label.extend_from_slice(&id);
        closure.update(label);
        closure.update(mac);
    }
    let mut cluster = Sha256::new();
    cluster.update(b"heptabao/v6/raft/cluster/v1");
    append_len_prefixed_hash(&mut cluster, root.cluster_id.as_bytes())?;
    Ok(V6ClosureObservation {
        cluster: cluster.finalize().into(),
        epoch: root.replay_epoch,
        root_digest,
        closure_digest: closure.finalize().into(),
        objects_checked: receipt.objects_read,
    })
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), V6RootAdmissionError> {
    let len = u32::try_from(bytes.len()).map_err(|_| V6RootAdmissionError::InvalidClosure)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn append_len_prefixed_hash(out: &mut Sha256, bytes: &[u8]) -> Result<(), V6RootAdmissionError> {
    let len = u32::try_from(bytes.len()).map_err(|_| V6RootAdmissionError::InvalidClosure)?;
    out.update(len.to_be_bytes());
    out.update(bytes);
    Ok(())
}

impl V6RootProposal {
    /// Additional check using a successfully authenticated V6 reader observation.
    /// Even a match is not proof of committed, applied or durable Raft authority.
    pub(crate) fn validate_observed_closure(
        self,
        observation: &V6ClosureObservation,
    ) -> Result<(), V6RootAdmissionError> {
        if self.cluster != observation.cluster()
            || self.epoch != observation.epoch()
            || self.next_root_digest != observation.root_digest()
        {
            return Err(V6RootAdmissionError::RootMismatch);
        }
        if self.object_closure_digest != observation.closure_digest() {
            return Err(V6RootAdmissionError::InvalidClosure);
        }
        Ok(())
    }
}
