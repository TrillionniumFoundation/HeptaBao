//! Fixed-width, feature-only V6 intent metadata staged through the real Raft
//! application-object journal. This is not a root publication, custody proof,
//! admission token or client write acknowledgement.
use crate::RecordRejection;
use std::fmt;

const MAGIC: &[u8; 5] = b"HBVI1";
pub(crate) const ENCODED_LEN: usize = 213;
const MAX_OBJECTS: u64 = 131_072;
const MAX_LEAF_BYTES: u64 = 256 * 1024;
const MIN_LEAF_BYTES: u64 = 25;

#[derive(Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeV6CommitIntent {
    pub cluster_digest: [u8; 32],
    pub epoch: u64,
    pub operation_digest: [u8; 32],
    pub closure_manifest_sha256: [u8; 32],
    pub object_count: u64,
    pub ciphertext_bytes: u64,
    pub prior_root_digest: [u8; 32],
    pub proposed_root_digest: [u8; 32],
    pub prior_generation: u64,
    pub proposed_generation: u64,
    pub expected_previous_commit_index: u64,
}

impl fmt::Debug for NativeV6CommitIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeV6CommitIntent")
            .field("epoch", &self.epoch)
            .field("object_count", &self.object_count)
            .field("ciphertext_bytes", &self.ciphertext_bytes)
            .field("prior_generation", &self.prior_generation)
            .field("proposed_generation", &self.proposed_generation)
            .field(
                "expected_previous_commit_index",
                &self.expected_previous_commit_index,
            )
            .finish_non_exhaustive()
    }
}
impl NativeV6CommitIntent {
    fn validate(&self) -> Result<(), RecordRejection> {
        if self.cluster_digest == [0; 32]
            || self.operation_digest == [0; 32]
            || self.closure_manifest_sha256 == [0; 32]
            || self.prior_root_digest == [0; 32]
            || self.proposed_root_digest == [0; 32]
            || self.proposed_root_digest == self.prior_root_digest
            || self.expected_previous_commit_index == 0
            || !(1..=MAX_OBJECTS).contains(&self.object_count)
            || self.prior_generation.checked_add(1) != Some(self.proposed_generation)
            || self
                .object_count
                .checked_mul(MIN_LEAF_BYTES)
                .is_none_or(|minimum| self.ciphertext_bytes < minimum)
            || self
                .object_count
                .checked_mul(MAX_LEAF_BYTES)
                .is_none_or(|maximum| self.ciphertext_bytes > maximum)
        {
            return Err(RecordRejection::Invalid);
        }
        Ok(())
    }

    pub fn encode(self) -> Result<Vec<u8>, RecordRejection> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(ENCODED_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.cluster_digest);
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.operation_digest);
        bytes.extend_from_slice(&self.closure_manifest_sha256);
        bytes.extend_from_slice(&self.object_count.to_be_bytes());
        bytes.extend_from_slice(&self.ciphertext_bytes.to_be_bytes());
        bytes.extend_from_slice(&self.prior_root_digest);
        bytes.extend_from_slice(&self.proposed_root_digest);
        bytes.extend_from_slice(&self.prior_generation.to_be_bytes());
        bytes.extend_from_slice(&self.proposed_generation.to_be_bytes());
        bytes.extend_from_slice(&self.expected_previous_commit_index.to_be_bytes());
        debug_assert_eq!(bytes.len(), ENCODED_LEN);
        Ok(bytes)
    }

    /// Strict canonical fixed-frame parser. A caller-controlled digest or
    /// encoded record can never bypass structural checks on Raft replay.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordRejection> {
        if bytes.len() != ENCODED_LEN {
            return Err(RecordRejection::Invalid);
        }
        let mut at = 0_usize;
        fn take<const N: usize>(
            bytes: &[u8],
            offset: &mut usize,
        ) -> Result<[u8; N], RecordRejection> {
            let end = offset.checked_add(N).ok_or(RecordRejection::Invalid)?;
            let result = bytes
                .get(*offset..end)
                .ok_or(RecordRejection::Invalid)?
                .try_into()
                .map_err(|_| RecordRejection::Invalid)?;
            *offset = end;
            Ok(result)
        }
        if &take::<5>(bytes, &mut at)? != MAGIC {
            return Err(RecordRejection::Invalid);
        }
        let cluster_digest = take::<32>(bytes, &mut at)?;
        let epoch = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        let operation_digest = take::<32>(bytes, &mut at)?;
        let closure_manifest_sha256 = take::<32>(bytes, &mut at)?;
        let object_count = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        let ciphertext_bytes = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        let prior_root_digest = take::<32>(bytes, &mut at)?;
        let proposed_root_digest = take::<32>(bytes, &mut at)?;
        let prior_generation = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        let proposed_generation = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        let expected_previous_commit_index = u64::from_be_bytes(take::<8>(bytes, &mut at)?);
        if at != ENCODED_LEN {
            return Err(RecordRejection::Invalid);
        }
        let candidate = Self {
            cluster_digest,
            epoch,
            operation_digest,
            closure_manifest_sha256,
            object_count,
            ciphertext_bytes,
            prior_root_digest,
            proposed_root_digest,
            prior_generation,
            proposed_generation,
            expected_previous_commit_index,
        };
        candidate.validate()?;
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> NativeV6CommitIntent {
        NativeV6CommitIntent {
            cluster_digest: [1; 32],
            epoch: 7,
            operation_digest: [2; 32],
            closure_manifest_sha256: [3; 32],
            object_count: 556,
            ciphertext_bytes: 139 * 1024 * 1024,
            prior_root_digest: [4; 32],
            proposed_root_digest: [5; 32],
            prior_generation: 20,
            proposed_generation: 21,
            expected_previous_commit_index: 100,
        }
    }
    #[test]
    fn exact_fixed_wire_and_boundaries() -> Result<(), RecordRejection> {
        let source = valid();
        let bytes = source.encode()?;
        assert_eq!(bytes.len(), ENCODED_LEN);
        assert_eq!(NativeV6CommitIntent::decode(&bytes)?, source);
        let mut changed = bytes.clone();
        changed[0] ^= 1;
        assert!(NativeV6CommitIntent::decode(&changed).is_err());
        let mut changed = bytes.clone();
        changed[6] ^= 1; // even a syntactically valid new identity changes bytes
        assert_ne!(NativeV6CommitIntent::decode(&changed)?, source);
        assert!(NativeV6CommitIntent::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut changed = bytes;
        changed.push(0);
        assert!(NativeV6CommitIntent::decode(&changed).is_err());
        Ok(())
    }
    #[test]
    fn committed_intent_cannot_be_published_by_v5_or_rewritten()
    -> Result<(), Box<dyn std::error::Error>> {
        let object = crate::SealedRecordObject::new_native_v6_commit_intent(valid())?;
        assert_eq!(
            object.reference().kind,
            crate::RecordObjectKind::NativeV6CommitIntent
        );
        let mut changed = object.sealed().to_vec();
        changed[42] ^= 1;
        assert!(
            crate::SealedRecordObject::new(object.reference().clone(), vec![], changed).is_err()
        );
        let mut wrong = object.reference().clone();
        wrong.payload_bytes += 1;
        assert!(crate::SealedRecordObject::new(wrong, vec![], object.sealed().to_vec()).is_err());
        assert!(
            crate::SealedRecordObject::new(
                object.reference().clone(),
                vec![object.reference().clone()],
                object.sealed().to_vec()
            )
            .is_err()
        );
        let legacy = crate::PublishedRecordRoot::new(
            crate::RecordRootBase::Empty,
            crate::ReplicatedEnvelope::new("v6-intent-never-v5-root", [9; 32], vec![7; 32])?,
            vec![object.reference().clone()],
        );
        assert!(
            legacy.is_err(),
            "V6 intent cannot enter a V5 published root"
        );
        Ok(())
    }

    #[test]
    fn malformed_claims_never_form_an_intent() {
        let base = valid();
        let mut x = base;
        x.cluster_digest = [0; 32];
        assert!(x.encode().is_err());
        let mut x = base;
        x.operation_digest = [0; 32];
        assert!(x.encode().is_err());
        let mut x = base;
        x.closure_manifest_sha256 = [0; 32];
        assert!(x.encode().is_err());
        let mut x = base;
        x.proposed_root_digest = x.prior_root_digest;
        assert!(x.encode().is_err());
        let mut x = base;
        x.object_count = 0;
        assert!(x.encode().is_err());
        let mut x = base;
        x.object_count = u64::MAX;
        assert!(x.encode().is_err());
        let mut x = base;
        x.ciphertext_bytes = u64::MAX;
        assert!(x.encode().is_err());
        let mut x = base;
        x.ciphertext_bytes = 1;
        assert!(x.encode().is_err());
        let mut x = base;
        x.prior_generation = u64::MAX;
        assert!(x.encode().is_err());
        let mut x = base;
        x.proposed_generation = 22;
        assert!(x.encode().is_err());
        let mut x = base;
        x.expected_previous_commit_index = 0;
        assert!(x.encode().is_err());
    }

    #[test]
    fn native_intent_preserves_the_actual_initial_replay_epoch() -> Result<(), RecordRejection> {
        let mut initial = valid();
        // A newly initialized real Service root begins at replay epoch zero.
        // The codec preserves that epoch; only a committed epoch transition
        // may change it. It is independent of nonzero Raft term/log identity.
        initial.epoch = 0;
        let encoded = initial.encode()?;
        assert_eq!(NativeV6CommitIntent::decode(&encoded)?, initial);
        Ok(())
    }
}
