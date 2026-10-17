//! Actual three-node Raft fixture support for the local Service installer.
//! Pins and ciphertext delivery here are explicit synthetic fixture inputs.
//! This module makes no TLS quorum claim; the separate pinned-mTLS test covers
//! that transport. Every root and read handle still comes from real consensus.
use super::*;
use crate::service::native_v6_ha_objects::NativeV6HaProposal;
use crate::state_record_root::RecordStateRoot;
use crate::state_records::StagedObject;
use heptabao_raft_runtime::{PublishedRecordRoot, RecordRootBase, SealedRecordObject};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

impl HaProcess {
    pub(crate) fn native_install_test_enable(&mut self) -> TestResult {
        if self.native_v6.is_some() {
            return Err("fixture native runtime already configured".into());
        }
        let native = Arc::new(NativeV6Runtime {
            identity: Arc::new(()),
            root: self.storage_dir.join("native-v6-ciphertext"),
            storage: OnceLock::new(),
            receiver: OnceLock::new(),
            root_source: OnceLock::new(),
            configured_pins: BTreeMap::from([(1, [21; 32]), (2, [22; 32]), (3, [23; 32])]),
            transport: self.forward_transport.clone(),
            eligible: true,
        });
        native.enable()?;
        self.native_v6 = Some(native);
        Ok(())
    }

    pub(crate) fn native_install_test_ready(&self) -> TestResult {
        let node = self.node.as_ref().ok_or("fixture node absent")?;
        self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let role = node.local_leader_observation()?;
                    let membership = node.membership_observation().await?;
                    if role.local_is_leader
                        && role.leader == Some(node.id())
                        && role.term == membership.term
                        && membership.committed
                        && !membership.joint
                        && membership.voters == BTreeSet::from([1, 2, 3])
                        && role.committed_index.is_some_and(|index| {
                            role.applied_index.is_some_and(|applied| applied >= index)
                        })
                        && membership
                            .voters
                            .iter()
                            .filter(|id| **id != node.id())
                            .all(|id| {
                                membership
                                    .peer_contact_ms
                                    .get(id)
                                    .is_some_and(|age| age.is_some_and(|age| age <= 400))
                                    && membership.peer_matched.get(id).is_some_and(|matched| {
                                        matched.is_some_and(|matched| {
                                            role.committed_index
                                                .is_some_and(|committed| matched >= committed)
                                        })
                                    })
                            })
                    {
                        let (witness, _, _) = node.application_read_witness().await?;
                        node.verify_application_read_witness(&witness).await?;
                        return Ok::<_, RemoteRaftError>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
        })??;
        Ok(())
    }

    pub(crate) fn native_install_test_anchor_v5(
        &self,
        root: &RecordStateRoot,
        objects: &[Arc<StagedObject>],
    ) -> TestResult<(NativeV6PeerEnrollment, u64)> {
        self.native_install_test_ready()?;
        let node = self.node.as_ref().ok_or("fixture node absent")?;
        let configured = self
            .native_v6
            .as_ref()
            .ok_or("fixture native runtime absent")?;
        self.runtime.block_on(async {
            for object in objects {
                let sealed = self.codec.seal_record_object(&root.address_key(), object)?;
                node.stage_application_object(node.next_production_client_serial().await?, &sealed)
                    .await?;
            }
            let sealed = self.codec.seal_record_root(
                "native-install-v5-source",
                &RecordRootBase::Empty,
                root,
            )?;
            let published = PublishedRecordRoot::new(
                RecordRootBase::Empty,
                ReplicatedEnvelope::new(
                    sealed.operation_id(),
                    sealed.digest(),
                    sealed.sealed().to_vec(),
                )?,
                root.references()
                    .map(crate::ha_state::runtime_reference)
                    .collect(),
            )?;
            let receipt = node
                .publish_application_root(node.next_production_client_serial().await?, &published)
                .await?;
            let enrollment = node
                .enroll_native_v6_peers(
                    node.next_production_client_serial().await?,
                    self.codec.native_v6_cluster_digest(),
                    root.replay_epoch,
                    configured.configured_pins.clone(),
                    Instant::now() + Duration::from_secs(5),
                )
                .await?;
            Ok((enrollment, receipt.log_index))
        })
    }

    pub(crate) fn native_install_test_with_source<T>(
        &self,
        f: impl FnOnce(&ClusterStateCodec, &LocalV6BlobStage) -> T,
    ) -> TestResult<T> {
        let native = self
            .native_v6
            .as_ref()
            .ok_or("fixture native runtime absent")?;
        let store = native.storage.get().ok_or("fixture native store absent")?;
        Ok(f(&self.codec, store))
    }

    pub(crate) fn native_install_test_store(&self) -> TestResult<Arc<LocalV6BlobStage>> {
        Ok(self
            .native_v6
            .as_ref()
            .and_then(|native| native.storage.get())
            .ok_or("fixture native store absent")?
            .clone())
    }

    pub(crate) fn native_install_test_copy_ciphertext(
        &self,
        source: &LocalV6BlobStage,
        proposal: &NativeV6HaProposal,
    ) -> TestResult {
        let target = self.native_install_test_store()?;
        let deadline = proposal.original_deadline();
        let mut gate = || {
            deadline
                .check()
                .map_err(|_| heptabao_raft_runtime::LocalV6BlobError::CorruptOrChanged)
        };
        // No NodeId argument or resulting local receipt counts as a peer vote.
        // These bytes solely prepare the actual storage inspected by installer.
        for reference in proposal.references() {
            deadline.check()?;
            let bytes = source.read_local(reference)?;
            target.stage_received_replica_checked(reference, &bytes, &mut gate)?;
        }
        let closure = target.persist_local_closure(proposal.references(), &mut gate)?;
        if closure.manifest_sha256() != proposal.intent().closure_manifest_sha256 {
            return Err("fixture closure mismatch".into());
        }
        Ok(())
    }

    pub(crate) fn native_install_test_publish(
        &self,
        proposal: &NativeV6HaProposal,
        enrollment: &NativeV6PeerEnrollment,
    ) -> TestResult<NativeV6PublishedRoot> {
        proposal.original_deadline().check()?;
        let node = self.node.as_ref().ok_or("fixture node absent")?;
        self.runtime.block_on(async {
            let object = SealedRecordObject::new_native_v6_commit_intent(proposal.intent())?;
            let receipt = node
                .stage_application_object(node.next_production_client_serial().await?, &object)
                .await?;
            let published = node
                .publish_native_v6_root(
                    node.next_production_client_serial().await?,
                    &proposal.intent(),
                    &receipt,
                    enrollment,
                    proposal.sealed_root().to_vec(),
                    proposal.original_deadline().instant(),
                )
                .await?;
            Ok(published)
        })
    }
}
