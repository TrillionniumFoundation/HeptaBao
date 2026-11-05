//! A real archive remains readable as old data after its source owners drop.
//! This alone is not a new-cluster restore, HA admission or DR qualification.
use super::*;
use crate::ha::native_v6_backup::validate_cold_native_v6_archive;

#[test]
fn cold_dr_archive_authenticates_without_old_selection_codec_or_donor() -> TestResult {
    let (files, mut service, key, token) = initialized()?;
    let cluster_id = service.state.as_ref().ok_or("state")?.cluster_id.clone();
    let codec = ClusterStateCodec::new(&cluster_id, [59; 32])?;
    let cluster = Cluster::new(files.path.join("cold-data-old-raft"))?;
    let (enrollment, prior_digest, prior_index) = enroll_and_anchor(&cluster, &codec, &service)?;
    assert_eq!(
        call(
            &mut service,
            "POST",
            "sys/internal/native-v6/activate",
            &token,
            json!({})
        )
        .status,
        204
    );
    for version in 1..=2 {
        assert_eq!(
            call(
                &mut service,
                "POST",
                "secret/data/cold-data",
                &token,
                json!({"options":{"cas":version-1},"data":{"version":version}})
            )
            .status,
            200
        );
    }
    let sender_path = files.path.join("cold-data-old-ciphertext");
    let sender = stage(&sender_path)?;
    let export_scope = archive_scope();
    let deadline = OriginalDeadline::capture()?;
    let state = service.state.as_ref().ok_or("state")?.clone();
    let plan = service
        .prepare_native_live_root_checked(&state, &mut |_| Ok(()))
        .map_err(|_| "actual source plan")?;
    let prepared = {
        let durable = service.durable.as_mut().ok_or("actual durable")?;
        let source =
            native_blob_source::NativeSource::new_checked(durable, plan.deadline, || Ok(()))?;
        prepare_native_v6_ha_objects(
            &plan,
            &codec,
            &enrollment,
            &sender,
            Some(&source),
            None,
            &mut || Ok(()),
        )?
    };
    let intent = intent(&prepared, &enrollment, prior_digest, prior_index);
    let proposal = prepared.into_proposal(&codec, &enrollment, intent, &mut || Ok(()))?;
    let published = cluster.runtime.block_on(async {
        let node = &cluster.nodes[0];
        let staged = node
            .stage_application_object(
                node.next_production_client_serial().await?,
                &SealedRecordObject::new_native_v6_commit_intent(intent)?,
            )
            .await?;
        node.publish_native_v6_root(
            node.next_production_client_serial().await?,
            &intent,
            &staged,
            &enrollment,
            proposal.sealed_root().to_vec(),
            Instant::now() + Duration::from_secs(5),
        )
        .await
    })?;
    let selection = NativeV6ArchiveSelection::from_committed(&enrollment, &published)?;
    let barrier = AeadBarrier::new(**service.barrier_key.as_ref().ok_or("barrier")?)?;
    let seal_identity: [u8; 32] = Sha256::digest(serde_json::to_vec(
        service.seal.as_ref().ok_or("seal metadata")?,
    )?)
    .into();
    let local_path = files.path.join("cold-data-original-local.pack");
    let local = prepare_native_v6_local_pack(
        service.durable.as_mut().ok_or("durable")?,
        &selection,
        private_file(&local_path)?,
        deadline,
        &mut || Ok(()),
        &mut |_, _| Ok(()),
    )?;
    let archive_path = files.path.join("cold-data.archive");
    let mut output = private_file(&archive_path)?;
    let report = write_native_v6_archive(
        &selection,
        local,
        &sender,
        seal_identity,
        &barrier,
        &mut output,
        &mut || Ok(()),
    )?;
    output.flush()?;
    let expected_migration = published.migration_source();
    let expected_publication = published.publication_log_id();
    let expected_intent_log = published.intent_log_id();
    let expected_enrollment = enrollment.digest();
    let local_digest = hash_file(&local_path)?;
    drop(output);
    drop((proposal, plan, state));
    drop((
        selection, published, enrollment, codec, cluster, service, sender, key, token,
    ));
    drop(export_scope);
    std::fs::rename(
        &sender_path,
        files.path.join("cold-data-old-ciphertext.quarantined"),
    )?;
    assert!(!sender_path.exists());

    let _read_scope = archive_scope();
    let (mut verified, facts) = validate_cold_native_v6_archive(
        ArchiveView::new(&archive_path)?,
        seal_identity,
        &barrier,
        OriginalDeadline::capture()?,
        &mut || Ok(()),
    )?;
    assert_eq!(verified.report(), report);
    assert_eq!(facts.cluster_digest(), intent.cluster_digest);
    assert!(facts.matches_cluster_id(&cluster_id));
    assert!(!facts.matches_cluster_id("another-cluster"));
    assert_eq!(facts.replay_epoch(), intent.epoch);
    assert_eq!(facts.root_digest(), intent.proposed_root_digest);
    assert_eq!(facts.raft_generation(), intent.proposed_generation);
    assert_eq!(facts.migration_digest(), expected_migration.0);
    assert_eq!(
        facts.migration_log(),
        [
            expected_migration.1.committed_leader_id().term,
            expected_migration.1.committed_leader_id().node_id,
            expected_migration.1.index,
        ]
    );
    assert_eq!(
        facts.publication_log(),
        [
            expected_publication.committed_leader_id().term,
            expected_publication.committed_leader_id().node_id,
            expected_publication.index,
        ]
    );
    assert_eq!(
        facts.intent_log(),
        [
            expected_intent_log.committed_leader_id().term,
            expected_intent_log.committed_leader_id().node_id,
            expected_intent_log.index,
        ]
    );
    assert_eq!(facts.enrollment_digest(), expected_enrollment);
    let copy_path = files.path.join("cold-data-recovered-local.pack");
    let mut copy = private_file(&copy_path)?;
    verified.copy_local_pack_to(&mut copy, &mut || Ok(()))?;
    copy.flush()?;
    assert_eq!(copy.metadata()?.len(), report.local.archive_bytes);
    assert_eq!(hash_file(&copy_path)?, local_digest);
    drop((copy, verified, facts));

    let mut header = [0; 232];
    File::open(&archive_path)?.read_exact(&mut header)?;
    let provenance_bytes = u32::from_be_bytes(header[8..12].try_into()?) as u64;
    let local_offset = 232 + provenance_bytes;
    for offset in [232 + 48, local_offset + 64, report.archive_bytes - 1] {
        let mut hostile = ArchiveView::new(&archive_path)?;
        hostile.flip(offset)?;
        assert!(
            validate_cold_native_v6_archive(
                hostile,
                seal_identity,
                &barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err()
        );
    }
    for length in [report.archive_bytes - 1, report.archive_bytes + 1, u64::MAX] {
        let mut hostile = ArchiveView::new(&archive_path)?;
        hostile.length = length;
        assert!(
            validate_cold_native_v6_archive(
                hostile,
                seal_identity,
                &barrier,
                OriginalDeadline::capture()?,
                &mut || Ok(())
            )
            .is_err()
        );
    }
    assert!(
        validate_cold_native_v6_archive(
            ArchiveView::new(&archive_path)?,
            [0; 32],
            &barrier,
            OriginalDeadline::capture()?,
            &mut || Ok(())
        )
        .is_err()
    );
    assert!(
        validate_cold_native_v6_archive(
            ArchiveView::new(&archive_path)?,
            seal_identity,
            &AeadBarrier::new([91; 32])?,
            OriginalDeadline::capture()?,
            &mut || Ok(())
        )
        .is_err()
    );
    let mut changed = ArchiveView::new(&archive_path)?;
    changed.flip(local_offset + 64)?;
    changed.active.set(false);
    let change = Rc::clone(&changed.active);
    let (mut verified, _) = validate_cold_native_v6_archive(
        changed,
        seal_identity,
        &barrier,
        OriginalDeadline::capture()?,
        &mut || Ok(()),
    )?;
    change.set(true);
    assert!(
        verified
            .copy_local_pack_to(&mut io::sink(), &mut || Ok(()))
            .is_err()
    );
    assert!(matches!(
        validate_cold_native_v6_archive(
            ArchiveView::new(&archive_path)?,
            seal_identity,
            &barrier,
            OriginalDeadline::capture()?,
            &mut || Err(NativeV6ArchiveError::Gate)
        ),
        Err(NativeV6ArchiveError::Gate)
    ));
    assert_eq!(hash_file(&archive_path)?, report.archive_sha256);
    Ok(())
}
