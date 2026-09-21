//! Actual object staging and root publication over the typed Raft state machine.
use super::*;
use crate::ha_state::runtime_reference;
use crate::state_record_root::{RecordStateRoot, StateIdentity};
use crate::state_records::{ObjectRef, StagedObject};
use heptabao_raft_runtime::{PublishedRecordRoot, RecordRootBase};

pub(crate) struct CommittedRecordState {
    pub(crate) root: RecordStateRoot,
    pub(crate) root_bytes: Zeroizing<Vec<u8>>,
    pub(crate) identity: StateIdentity,
    pub(crate) read_cursor: Option<ValidatedReadCursor>,
}

impl HaProcess {
    fn collect_record_garbage(&self, expected_root: [u8; 32]) -> Result<(), String> {
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        loop {
            let ids = self
                .runtime
                .block_on(node.prunable_application_objects(expected_root, 256))
                .map_err(|error| error.to_string())?;
            if ids.is_empty() {
                break;
            }
            let serial = self
                .runtime
                .block_on(node.next_production_client_serial())
                .map_err(|error| error.to_string())?;
            self.runtime
                .block_on(node.prune_application_objects(serial, expected_root, &ids))
                .map_err(|error| error.to_string())?;
        }
        self.record_commits_since_gc.store(0, Ordering::Relaxed);
        Ok(())
    }

    pub(crate) fn commit_record_state(
        &self,
        operation: &str,
        expected: &StateIdentity,
        root_bytes: &[u8],
        objects: &[Arc<StagedObject>],
    ) -> Result<CommitReceipt, String> {
        let root =
            RecordStateRoot::decode(root_bytes).map_err(|_| "invalid record publication root")?;
        let identity = root
            .identity()
            .map_err(|_| "invalid record publication identity")?;
        if root.cluster_id != self.cluster_id {
            return Err("record root belongs to another cluster".into());
        }
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        if self.runtime.block_on(node.current_leader()) != Some(node.id()) {
            return Err("record publication requires current leader".into());
        }
        self.runtime
            .block_on(node.ensure_linearizable())
            .map_err(|error| error.to_string())?;
        let (_, published) = self
            .runtime
            .block_on(node.record_root_at_generation())
            .map_err(|error| error.to_string())?;
        let base = if let Some(previous) = published.as_ref() {
            let CommittedStateDescriptor::RecordsV5(verified) = self
                .codec
                .open_committed_descriptor(
                    previous.envelope().operation_id(),
                    previous.envelope().digest(),
                    previous.envelope().sealed(),
                )
                .map_err(|error| error.to_string())?
            else {
                return Err("record publication has no authenticated record root".into());
            };
            if verified.base != previous.base()
                || verified
                    .root
                    .references()
                    .map(runtime_reference)
                    .collect::<Vec<_>>()
                    != previous.direct_refs()
            {
                return Err("record publication metadata authentication failed".into());
            }
            let observed = verified
                .root
                .identity()
                .map_err(|_| "invalid committed record identity")?;
            if &observed != expected {
                return Err("record publication base conflicts with committed root".into());
            }
            RecordRootBase::RecordsV5(observed.digest())
        } else if let Some(previous) = self
            .runtime
            .block_on(node.latest_envelope())
            .map_err(|error| error.to_string())?
        {
            if *expected != StateIdentity::Legacy(previous.digest()) {
                return Err("record migration base conflicts with legacy state".into());
            }
            let descriptor = self
                .codec
                .open_committed_descriptor(
                    previous.operation_id(),
                    previous.digest(),
                    previous.sealed(),
                )
                .map_err(|error| error.to_string())?;
            // Preserve the explicit older HBSR1 migration boundary. V4 owner
            // commits are the supported predecessor for record conversion.
            if !matches!(descriptor,CommittedStateDescriptor::Chunked(ref manifest) if manifest.owner_manifest_digest.is_some())
            {
                return Err("record migration requires an authenticated HBSM4 owner state".into());
            }
            RecordRootBase::Legacy(previous.digest())
        } else {
            // Only Service's authenticated initial-anchor path may call this
            // while the cluster has no application publication.
            RecordRootBase::Empty
        };
        let key = root.address_key();
        let mut staged = Vec::new();
        let mut estimated_bytes = 0_usize;
        for object in objects {
            let reference = runtime_reference(object.reference());
            if let Some(existing) = self
                .runtime
                .block_on(node.application_object(&reference))
                .map_err(|error| error.to_string())?
            {
                let plaintext = self
                    .codec
                    .open_record_object(&key, object.reference(), &existing)
                    .map_err(|error| error.to_string())?;
                if plaintext.as_slice() != object.bytes()
                    || existing.children()
                        != object
                            .children()
                            .iter()
                            .map(runtime_reference)
                            .collect::<Vec<_>>()
                {
                    return Err("reused application object differs from staged content".into());
                }
            } else {
                let sealed = self
                    .codec
                    .seal_record_object(&key, object)
                    .map_err(|error| error.to_string())?;
                estimated_bytes = estimated_bytes
                    .checked_add(
                        serde_json::to_vec(&sealed)
                            .map_err(|_| "object size encoding failed")?
                            .len()
                            + 128,
                    )
                    .ok_or("application object byte count overflow")?;
                staged.push(sealed);
            }
        }
        let (_, usage) = self
            .runtime
            .block_on(node.application_record_usage())
            .map_err(|error| error.to_string())?;
        let writes = self.record_commits_since_gc.load(Ordering::Relaxed);
        if writes == 0
            || writes >= 64
            || usage
                .encoded_bytes
                .saturating_add(estimated_bytes)
                .saturating_add(256 * 1024)
                >= usage.encoded_limit
        {
            self.collect_record_garbage(
                published
                    .as_ref()
                    .map(|p| p.envelope().digest())
                    .unwrap_or([0; 32]),
            )?;
            // Garbage collection may retire reusable unpublished objects. The
            // complete candidate delta still owns their bytes and must restage
            // them before root publication; do not trust an earlier existence check.
            staged.clear();
            for object in objects {
                let reference = runtime_reference(object.reference());
                if self
                    .runtime
                    .block_on(node.application_object(&reference))
                    .map_err(|error| error.to_string())?
                    .is_none()
                {
                    staged.push(
                        self.codec
                            .seal_record_object(&key, object)
                            .map_err(|error| error.to_string())?,
                    );
                }
            }
        }
        for object in &staged {
            let serial = self
                .runtime
                .block_on(node.next_production_client_serial())
                .map_err(|error| error.to_string())?;
            let receipt = self
                .runtime
                .block_on(node.stage_application_object(serial, object))
                .map_err(|error| error.to_string())?;
            if receipt.leader_id != node.id() || receipt.envelope_digest != object.reference().id {
                return Err("staged application object receipt differs from payload".into());
            }
        }
        let proposal = self
            .codec
            .seal_record_root(operation, &base, &root)
            .map_err(|error| error.to_string())?;
        let envelope = ReplicatedEnvelope::new(
            operation.to_owned(),
            proposal.digest(),
            proposal.sealed().to_vec(),
        )
        .map_err(|error| error.to_string())?;
        let publication = PublishedRecordRoot::new(
            base,
            envelope,
            root.references().map(runtime_reference).collect(),
        )
        .map_err(|error| error.to_string())?;
        let serial = self
            .runtime
            .block_on(node.next_production_client_serial())
            .map_err(|error| error.to_string())?;
        let receipt = self
            .runtime
            .block_on(node.publish_application_root(serial, &publication))
            .map_err(|error| error.to_string())?;
        if receipt.leader_id != node.id() || receipt.envelope_digest != identity.digest() {
            return Err("application root receipt mismatch".into());
        }
        self.record_commits_since_gc.fetch_add(1, Ordering::Relaxed);
        Ok(receipt)
    }

    pub(crate) fn read_record_object(
        &self,
        root: &RecordStateRoot,
        reference: &ObjectRef,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        if root.cluster_id != self.cluster_id {
            return Err("object root belongs to another cluster".into());
        }
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        let object = self
            .runtime
            .block_on(node.application_object(&runtime_reference(reference)))
            .map_err(|error| error.to_string())?
            .ok_or("committed application object is absent")?;
        self.codec
            .open_record_object(&root.address_key(), reference, &object)
            .map_err(|error| error.to_string())
    }

    pub(super) fn read_record_root_if_present(
        &self,
        known: Option<&ValidatedReadCursor>,
    ) -> Result<Option<CommittedStateRead>, String> {
        let node = self.node.as_ref().ok_or("HA process is shut down")?;
        read_record_application(
            &self.codec,
            known,
            || {
                self.runtime
                    .block_on(node.ensure_linearizable())
                    .map_err(|error| error.to_string())
            },
            || {
                self.runtime
                    .block_on(node.record_root_at_generation())
                    .map_err(|error| error.to_string())
            },
        )
    }

    pub(crate) fn record_cursor_current(&self, cursor: &ValidatedReadCursor) -> bool {
        self.node.as_ref().is_some_and(|node| {
            cursor.records_v5
                && self.runtime.block_on(node.application_state_generation()) == cursor.generation
        })
    }
}

// The cursor remains provisional until Service authenticates the complete object
// graph, persists the root and verifies the generation is still current.
fn read_record_application(
    codec: &ClusterStateCodec,
    known: Option<&ValidatedReadCursor>,
    ensure_linearizable: impl FnOnce() -> Result<(), String>,
    current: impl FnOnce() -> Result<(u64, Option<PublishedRecordRoot>), String>,
) -> Result<Option<CommittedStateRead>, String> {
    ensure_linearizable()?;
    let (generation, Some(published)) = current()? else {
        return Ok(None);
    };
    let envelope = published.envelope();
    let CommittedStateDescriptor::RecordsV5(decoded) = codec
        .open_committed_descriptor(
            envelope.operation_id(),
            envelope.digest(),
            envelope.sealed(),
        )
        .map_err(|error| error.to_string())?
    else {
        return Err("committed record root has the wrong envelope format".into());
    };
    if decoded.base != published.base()
        || decoded
            .root
            .references()
            .map(runtime_reference)
            .collect::<Vec<_>>()
            != published.direct_refs()
    {
        return Err("committed application root metadata authentication failed".into());
    }
    let identity = manifest_envelope_identity(envelope);
    if known.is_some_and(|cursor| {
        cursor.records_v5 && cursor.generation == generation && cursor.envelope_identity == identity
    }) {
        return Ok(Some(CommittedStateRead::Unchanged));
    }
    Ok(Some(CommittedStateRead::Records(Box::new(
        CommittedRecordState {
            identity: StateIdentity::RecordsV5(envelope.digest()),
            root: decoded.root,
            root_bytes: decoded.bytes,
            read_cursor: Some(ValidatedReadCursor {
                generation,
                envelope_identity: identity,
                records_v5: true,
            }),
        },
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_record_root::{OWNER_NAMES, OpaqueOwnerRef, digest_owner};
    use crate::state_records::{AddressKey, Kv1Root};
    use std::cell::Cell;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        codec: ClusterStateCodec,
        root: RecordStateRoot,
        published: PublishedRecordRoot,
        generation: u64,
    }
    impl Fixture {
        fn new() -> TestResult<Self> {
            let key = AddressKey::from_bytes([7; 32]);
            let owners = OWNER_NAMES
                .into_iter()
                .map(|name| {
                    let object = StagedObject::owner_chunk(&key, b"{}")?;
                    Ok(OpaqueOwnerRef {
                        name: name.into(),
                        total_bytes: 2,
                        chunks: vec![object.reference().clone()],
                        digest: digest_owner(&key, name, b"{}").map_err(|_| "owner")?,
                    })
                })
                .collect::<TestResult<Vec<_>>>()?;
            let root = RecordStateRoot::new(
                36,
                "records-read-test".into(),
                0,
                owners.try_into().map_err(|_| "owners")?,
                Kv1Root {
                    reference: None,
                    height: 0,
                },
                [7; 32],
            )
            .map_err(|_| "root")?;
            let codec = ClusterStateCodec::new(&root.cluster_id, [3; 32])?;
            let base = RecordRootBase::Legacy([1; 32]);
            let proposal = codec.seal_record_root("record-read", &base, &root)?;
            let envelope = ReplicatedEnvelope::new(
                proposal.operation_id(),
                proposal.digest(),
                proposal.sealed().to_vec(),
            )?;
            let published = PublishedRecordRoot::new(
                base,
                envelope,
                root.references().map(runtime_reference).collect(),
            )?;
            Ok(Self {
                codec,
                root,
                published,
                generation: 19,
            })
        }
        fn read(
            &self,
            known: Option<&ValidatedReadCursor>,
        ) -> Result<Option<CommittedStateRead>, String> {
            read_record_application(
                &self.codec,
                known,
                || Ok(()),
                || Ok((self.generation, Some(self.published.clone()))),
            )
        }
        fn materialize(&self) -> TestResult<CommittedRecordState> {
            match self.read(None)? {
                Some(CommittedStateRead::Records(record)) => Ok(*record),
                _ => Err("not record".into()),
            }
        }
    }
    #[test]
    fn typed_cursor_authenticates_root_and_never_bypasses_read_index() -> TestResult {
        let fixture = Fixture::new()?;
        let first = fixture.materialize()?;
        assert_eq!(
            first.identity,
            fixture.root.identity().map_err(|_| "identity")?
        );
        assert!(matches!(
            fixture.read(first.read_cursor.as_ref())?,
            Some(CommittedStateRead::Unchanged)
        ));
        let reads = Cell::new(0);
        assert!(
            read_record_application(
                &fixture.codec,
                first.read_cursor.as_ref(),
                || Err("quorum lost".into()),
                || {
                    reads.set(reads.get() + 1);
                    Ok((fixture.generation, Some(fixture.published.clone())))
                }
            )
            .is_err()
        );
        assert_eq!(reads.get(), 0);
        Ok(())
    }
    #[test]
    fn legacy_cursor_or_changed_generation_cannot_reuse_record_evidence() -> TestResult {
        let mut fixture = Fixture::new()?;
        let first = fixture.materialize()?;
        let mut cursor = first.read_cursor.ok_or("cursor")?;
        cursor.records_v5 = false;
        assert!(matches!(
            fixture.read(Some(&cursor))?,
            Some(CommittedStateRead::Records(_))
        ));
        cursor.records_v5 = true;
        fixture.generation += 1;
        assert!(matches!(
            fixture.read(Some(&cursor))?,
            Some(CommittedStateRead::Records(_))
        ));
        Ok(())
    }
    #[test]
    fn warm_record_cursor_does_not_hide_tampered_envelope_base_or_direct_references() -> TestResult
    {
        let mut fixture = Fixture::new()?;
        let first = fixture.materialize()?;
        let original = fixture.published.clone();
        let envelope = original.envelope();
        fixture.published = PublishedRecordRoot::new(
            RecordRootBase::RecordsV5([1; 32]),
            envelope.clone(),
            original.direct_refs().to_vec(),
        )?;
        assert!(fixture.read(first.read_cursor.as_ref()).is_err());
        let mut refs = original.direct_refs().to_vec();
        refs[0].id[0] ^= 1;
        fixture.published = PublishedRecordRoot::new(original.base(), envelope.clone(), refs)?;
        assert!(fixture.read(first.read_cursor.as_ref()).is_err());
        let mut bytes = envelope.sealed().to_vec();
        *bytes.last_mut().ok_or("cipher")? ^= 1;
        let altered = ReplicatedEnvelope::new(envelope.operation_id(), envelope.digest(), bytes)?;
        fixture.published =
            PublishedRecordRoot::new(original.base(), altered, original.direct_refs().to_vec())?;
        assert!(fixture.read(first.read_cursor.as_ref()).is_err());
        Ok(())
    }
}
