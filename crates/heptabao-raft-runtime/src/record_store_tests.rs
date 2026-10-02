use super::*;
use crate::records::RecordCommand;
use crate::records_tests::{owner, root as publication};
use crate::state_machine::ApplicationRequest;
use crate::{RecordRejection, RecordRootBase};
use std::sync::atomic::{AtomicU64, Ordering};
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "heptabao-record-runtime-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}
async fn apply(store: &mut DurableStateMachine, request: ApplicationRequest) {
    let entry = EntryOf::<TypeConfig> {
        log_id: openraft::LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 1,
                node_id: 1,
            },
            index: store.last_applied_log_index().await.unwrap_or(0) + 1,
        },
        payload: EntryPayload::Normal(request),
    };
    RaftStateMachine::apply(
        store,
        futures::stream::iter([Ok::<_, io::Error>((entry, None))]),
    )
    .await
    .expect("actual durable journal apply");
}
fn request(command: RecordCommand) -> ApplicationRequest {
    ApplicationRequest::records(1, command).expect("bounded request")
}

#[tokio::test]
async fn staged_objects_survive_replay_without_publication_rejections_advance_and_snapshot_three_restores()
 {
    let path = root();
    let mut store = DurableStateMachine::create(&path).expect("create");
    let object = owner(1);
    apply(
        &mut store,
        request(RecordCommand::Stage {
            object: object.clone(),
        }),
    )
    .await;
    let generation = store.generation().await;
    assert_eq!(store.record_root_at_generation().await, (generation, None));
    drop(store);
    let mut store = DurableStateMachine::open_existing(&path).expect("replay staged object");
    assert_eq!(
        store
            .record_object(object.reference())
            .await
            .expect("read object"),
        Some(object.clone())
    );
    assert_eq!(store.record_root_at_generation().await, (generation, None));
    let bad = publication(
        RecordRootBase::RecordsV5([9; 32]),
        2,
        vec![object.reference().clone()],
    );
    apply(&mut store, request(RecordCommand::Publish { root: bad })).await;
    assert_eq!(store.generation().await, generation + 1);
    assert_eq!(store.last_applied_log_index().await, Some(2));
    assert!(store.record_root_at_generation().await.1.is_none());
    let root = publication(RecordRootBase::Empty, 2, vec![object.reference().clone()]);
    apply(
        &mut store,
        request(RecordCommand::Publish { root: root.clone() }),
    )
    .await;
    let snapshot = RaftSnapshotBuilder::build_snapshot(&mut store)
        .await
        .expect("format3 checkpoint");
    assert_eq!(store.bundle.lock().await.format_version, 3);
    let bytes = snapshot.snapshot.into_inner();
    assert!(serde_json::from_slice::<openraft_memstore::MemStoreStateMachine>(&bytes).is_err());
    let follower_path = path.with_extension("follower");
    let mut follower = DurableStateMachine::create(&follower_path).expect("follower");
    RaftStateMachine::install_snapshot(&mut follower, &snapshot.meta, Cursor::new(bytes))
        .await
        .expect("install same typed decoder");
    assert_eq!(
        follower.record_root_at_generation().await.1,
        Some(root.clone())
    );
    drop(follower);
    let follower =
        DurableStateMachine::open_existing(&follower_path).expect("follower durable reopen");
    assert_eq!(
        follower.record_root_at_generation().await.1,
        Some(root.clone())
    );
    drop(follower);
    drop(store);
    let reopened = DurableStateMachine::open_existing(&path).expect("checkpoint reopen");
    assert_eq!(reopened.record_root_at_generation().await.1, Some(root));
    assert_eq!(
        reopened
            .record_inventory(None, 256)
            .await
            .expect("inventory")
            .1,
        vec![object.reference().clone()]
    );
    drop(reopened);
    fs::remove_dir_all(path).expect("cleanup");
    fs::remove_dir_all(follower_path).expect("cleanup follower");
}

#[tokio::test]
async fn first_publication_reclaims_only_fixed_legacy_clients_atomically_and_replays() {
    let path = root();
    let mut store = DurableStateMachine::create(&path).expect("create");
    let legacy = crate::ReplicatedEnvelope::new("legacy", [8; 32], vec![4; 100]).expect("legacy");
    for (client, status) in [
        (crate::records::PRODUCTION_CLIENT, legacy.encoded_status()),
        (
            "heptabao-production-ha-chunk:000:0",
            "staged legacy chunk".into(),
        ),
        ("qualification", "retained test state".into()),
        (
            "heptabao-production-ha-chunk:999:9",
            "not a fixed production chunk".into(),
        ),
    ] {
        apply(
            &mut store,
            openraft_memstore::ClientRequest {
                client: client.into(),
                serial: 1,
                status,
            }
            .into(),
        )
        .await;
    }
    // The retained snapshot intentionally remains old until a new checkpoint.
    RaftSnapshotBuilder::build_snapshot(&mut store)
        .await
        .expect("legacy snapshot2");
    let a = owner(1);
    let missing = owner(2);
    apply(
        &mut store,
        request(RecordCommand::Stage { object: a.clone() }),
    )
    .await;
    let before = store.get_state_machine().await.client_status;
    apply(
        &mut store,
        request(RecordCommand::Publish {
            root: publication(
                RecordRootBase::Legacy([8; 32]),
                3,
                vec![missing.reference().clone()],
            ),
        }),
    )
    .await;
    assert_eq!(store.get_state_machine().await.client_status, before);
    let pubroot = publication(
        RecordRootBase::Legacy([8; 32]),
        3,
        vec![a.reference().clone()],
    );
    apply(
        &mut store,
        request(RecordCommand::Publish {
            root: pubroot.clone(),
        }),
    )
    .await;
    let state = store.get_state_machine().await;
    assert!(
        !state
            .client_status
            .contains_key(crate::records::PRODUCTION_CLIENT)
    );
    assert!(
        !state
            .client_status
            .contains_key("heptabao-production-ha-chunk:000:0")
    );
    assert_eq!(state.client_status.len(), 2);
    drop(store);
    let mut store =
        DurableStateMachine::open_existing(&path).expect("journal replay across old snapshot");
    assert_eq!(
        store.get_state_machine().await.client_status,
        state.client_status
    );
    assert_eq!(store.record_root_at_generation().await.1, Some(pubroot));
    RaftSnapshotBuilder::build_snapshot(&mut store)
        .await
        .expect("new compact record snapshot");
    drop(store);
    let reopened = DurableStateMachine::open_existing(&path).expect("format3 reopen");
    assert_eq!(reopened.get_state_machine().await.client_status.len(), 2);
    drop(reopened);
    fs::remove_dir_all(path).expect("cleanup");
}

#[tokio::test]
async fn malformed_snapshot_or_low_disk_budget_cannot_replace_published_state() {
    let path = root();
    let mut store = DurableStateMachine::create(&path).expect("create");
    let object = owner(1);
    apply(
        &mut store,
        request(RecordCommand::Stage {
            object: object.clone(),
        }),
    )
    .await;
    apply(
        &mut store,
        request(RecordCommand::Publish {
            root: publication(RecordRootBase::Empty, 2, vec![object.reference().clone()]),
        }),
    )
    .await;
    let before = store.record_root_at_generation().await;
    let bundle_bytes = fs::read(store.state_path()).expect("bundle");
    let journal_bytes = fs::read(state_journal_path(store.state_path())).expect("journal");
    store.artifact_bound = 64;
    assert!(
        RaftSnapshotBuilder::build_snapshot(&mut store)
            .await
            .is_err()
    );
    assert_eq!(store.record_root_at_generation().await, before);
    assert_eq!(fs::read(store.state_path()).expect("bundle"), bundle_bytes);
    assert_eq!(
        fs::read(state_journal_path(store.state_path())).expect("journal"),
        journal_bytes
    );
    store.artifact_bound = MAX_DURABLE_ARTIFACT_BYTES;
    let state = store.get_state_machine().await;
    let meta = SnapshotMetaOf::<TypeConfig> {
        last_log_id: state.last_applied_log,
        last_membership: state.last_membership.clone(),
    };
    let mut damaged: serde_json::Value =
        serde_json::from_slice(&state.snapshot_bytes().expect("snapshot")).expect("json");
    damaged["state"]["records_v5"]["objects"] = serde_json::json!({});
    assert!(
        RaftStateMachine::install_snapshot(
            &mut store,
            &meta,
            Cursor::new(serde_json::to_vec(&damaged).expect("damaged"))
        )
        .await
        .is_err()
    );
    assert_eq!(store.record_root_at_generation().await, before);
    assert_eq!(fs::read(store.state_path()).expect("bundle"), bundle_bytes);
    assert_eq!(
        store.prunable_records([0; 32], 1).await,
        Err(RecordRejection::StaleRoot)
    );
    drop(store);
    fs::remove_dir_all(path).expect("cleanup");
}

#[tokio::test]
async fn legacy_cleanup_journal_replay_snapshot_fence_and_failed_command_are_atomic() {
    let path = root();
    let mut store = DurableStateMachine::create(&path).expect("create");
    let manifest = crate::ReplicatedEnvelope::new("legacy-manifest", [71; 32], vec![71; 100])
        .expect("manifest");
    let chunk =
        crate::ReplicatedEnvelope::new("legacy-chunk", [72; 32], vec![72; 100]).expect("chunk");
    let expected = crate::LegacyStatusIdentity::inspect(&manifest.encoded_status())
        .expect("identity")
        .1;
    let active = vec![crate::LegacyChunkRef {
        index: 0,
        slot: 0,
        identity: crate::LegacyStatusIdentity::inspect(&chunk.encoded_status())
            .expect("chunk identity")
            .1,
    }];
    for (client, status) in [
        (crate::records::PRODUCTION_CLIENT, manifest.encoded_status()),
        ("heptabao-production-ha-chunk:000:0", chunk.encoded_status()),
        ("heptabao-production-ha-chunk:000:1", chunk.encoded_status()),
        ("qualification", "retained".into()),
    ] {
        apply(
            &mut store,
            openraft_memstore::ClientRequest {
                client: client.into(),
                serial: 1,
                status,
            }
            .into(),
        )
        .await;
    }
    RaftSnapshotBuilder::build_snapshot(&mut store)
        .await
        .expect("old format2 snapshot");
    let before = store.get_state_machine().await.client_status;
    let generation = store.generation().await;
    let mut wrong = expected;
    wrong.status_sha256[0] ^= 1;
    apply(
        &mut store,
        request(RecordCommand::RetainLegacyChunks {
            expected_manifest: wrong,
            active: active.clone(),
        }),
    )
    .await;
    assert_eq!(store.get_state_machine().await.client_status, before);
    assert_eq!(store.generation().await, generation + 1);
    assert!(store.get_state_machine().await.records_v5.is_none());
    apply(
        &mut store,
        request(RecordCommand::RetainLegacyChunks {
            expected_manifest: expected,
            active: active.clone(),
        }),
    )
    .await;
    let after = store.get_state_machine().await.client_status;
    assert_eq!(
        after.get(crate::records::PRODUCTION_CLIENT),
        before.get(crate::records::PRODUCTION_CLIENT)
    );
    assert!(!after.contains_key("heptabao-production-ha-chunk:000:1"));
    drop(store);
    let mut store = DurableStateMachine::open_existing(&path).expect("replay cleanup and fence");
    assert_eq!(store.get_state_machine().await.client_status, after);
    assert!(store.record_root_at_generation().await.1.is_none());
    assert_eq!(store.bundle.lock().await.format_version, 3);
    let snapshot = RaftSnapshotBuilder::build_snapshot(&mut store)
        .await
        .expect("prepared snapshot3");
    assert!(
        serde_json::from_slice::<openraft_memstore::MemStoreStateMachine>(
            snapshot.snapshot.get_ref()
        )
        .is_err()
    );
    drop(store);
    let mut store = DurableStateMachine::open_existing(&path).expect("reopen prepared checkpoint");
    apply(
        &mut store,
        openraft_memstore::ClientRequest {
            client: crate::records::PRODUCTION_CLIENT.into(),
            serial: 9,
            status: chunk.encoded_status(),
        }
        .into(),
    )
    .await;
    assert_eq!(store.get_state_machine().await.client_status, after);
    // The unchanged physical snapshot bound remains enforced after cleanup.
    let saved = fs::read(store.state_path()).expect("bundle before failure");
    let journal = fs::read(state_journal_path(store.state_path())).expect("journal before failure");
    let generation = store.generation().await;
    store.artifact_bound = 128;
    assert!(
        RaftSnapshotBuilder::build_snapshot(&mut store)
            .await
            .is_err()
    );
    assert_eq!(store.generation().await, generation);
    assert_eq!(
        fs::read(store.state_path()).expect("bundle unchanged"),
        saved
    );
    assert_eq!(
        fs::read(state_journal_path(store.state_path())).expect("journal unchanged"),
        journal
    );
    drop(store);
    let reopened =
        DurableStateMachine::open_existing(&path).expect("failed snapshot remains reopenable");
    assert_eq!(reopened.get_state_machine().await.client_status, after);
    drop(reopened);
    fs::remove_dir_all(path).expect("cleanup");
}

#[tokio::test]
async fn replacement_admission_is_read_only_cas_and_capacity_checked_before_stage() {
    let path = root();
    let mut store = DurableStateMachine::create(&path).expect("create");
    let old = owner(31);
    apply(
        &mut store,
        request(RecordCommand::Stage {
            object: old.clone(),
        }),
    )
    .await;
    let first = publication(RecordRootBase::Empty, 32, vec![old.reference().clone()]);
    apply(
        &mut store,
        request(RecordCommand::Publish {
            root: first.clone(),
        }),
    )
    .await;
    let next = owner(33);
    let publication = publication(
        RecordRootBase::RecordsV5(first.envelope().digest()),
        34,
        vec![old.reference().clone(), next.reference().clone()],
    );
    let generation = store.generation().await;
    let root_before = store.record_root_at_generation().await;
    let file = std::fs::read(store.state_path()).expect("bundle");
    let journal_path = state_journal_path(store.state_path());
    let journal = std::fs::read(&journal_path).expect("journal");
    store
        .preflight_record_publication(&[old.clone(), next.clone()], &publication)
        .await
        .expect("admission");
    assert!(
        store
            .record_object(next.reference())
            .await
            .expect("object")
            .is_none()
    );
    let conflict = crate::SealedRecordObject::new(old.reference().clone(), vec![], vec![99; 62])
        .expect("conflict");
    assert_eq!(
        store
            .preflight_record_publication(&[conflict, next.clone()], &publication)
            .await,
        Err(RecordRejection::ImmutableConflict)
    );
    let stale = crate::records_tests::root(
        RecordRootBase::RecordsV5([99; 32]),
        35,
        vec![next.reference().clone()],
    );
    assert_eq!(
        store
            .preflight_record_publication(std::slice::from_ref(&next), &stale)
            .await,
        Err(RecordRejection::StaleRoot)
    );
    store.artifact_bound = 128;
    assert_eq!(
        store
            .preflight_record_publication(&[next], &publication)
            .await,
        Err(RecordRejection::Budget)
    );
    assert_eq!(store.generation().await, generation);
    assert_eq!(store.record_root_at_generation().await, root_before);
    assert_eq!(
        std::fs::read(store.state_path()).expect("bundle unchanged"),
        file
    );
    assert_eq!(
        std::fs::read(journal_path).expect("journal unchanged"),
        journal
    );
    drop(store);
    let reopened = DurableStateMachine::open_existing(&path).expect("unchanged state reopens");
    assert_eq!(reopened.record_root_at_generation().await, root_before);
    drop(reopened);
    std::fs::remove_dir_all(path).expect("cleanup");
}
