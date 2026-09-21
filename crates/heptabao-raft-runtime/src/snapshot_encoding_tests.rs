use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "heptabao-snapshot-{label}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn apply_value(store: &mut DurableStateMachine, value: String) {
    let entry = EntryOf::<TypeConfig> {
        log_id: openraft::LogId {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 1,
                node_id: 1,
            },
            index: store.last_applied_log_index().await.unwrap_or(0) + 1,
        },
        payload: EntryPayload::Normal(
            openraft_memstore::ClientRequest {
                client: "selected".into(),
                serial: 1,
                status: value,
            }
            .into(),
        ),
    };
    RaftStateMachine::apply(
        store,
        futures::stream::iter([Ok::<_, io::Error>((entry, None))]),
    )
    .await
    .expect("apply value through actual journal");
}

fn disk_view(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(root)
        .expect("read fixture directory")
        .map(|entry| {
            let path = entry.expect("entry").path();
            (
                path.file_name()
                    .expect("leaf")
                    .to_string_lossy()
                    .into_owned(),
                fs::read(path).expect("read file"),
            )
        })
        .collect()
}

#[tokio::test]
async fn snapshot_capacity_failure_preserves_bundle_journal_generation_and_reopen() {
    let root = root("capacity");
    let mut store = DurableStateMachine::create(&root).expect("create");
    apply_value(&mut store, "previous-checkpoint".into()).await;
    let prior = store.build_snapshot().await.expect("existing snapshot");
    let previous_snapshot = prior.snapshot.into_inner();
    let value = "a".repeat(8192);
    apply_value(&mut store, value.clone()).await;
    let files = disk_view(&root);
    let generation = store.generation().await;
    let applied = store.last_applied_log_index().await;
    // Production uses the same persistence function with 128 MiB. A small injected
    // bound proves the actual build/install call sites cannot publish on rejection.
    store.artifact_bound = 1024;
    let error = store
        .build_snapshot()
        .await
        .expect_err("encoded bundle exceeds bound");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(disk_view(&root), files);
    assert_eq!(store.generation().await, generation);
    assert_eq!(store.last_applied_log_index().await, applied);
    assert_eq!(
        store
            .bundle
            .lock()
            .await
            .current_snapshot
            .as_ref()
            .expect("retained snapshot")
            .data,
        previous_snapshot
    );
    assert_eq!(
        store.client_status("selected").await.as_deref(),
        Some(value.as_str())
    );

    let state = store.get_state_machine().await;
    let data = serde_json::to_vec(&state).expect("encode received snapshot");
    let meta = SnapshotMetaOf::<TypeConfig> {
        last_log_id: state.last_applied_log,
        last_membership: state.last_membership,
    };
    assert!(
        RaftStateMachine::install_snapshot(&mut store, &meta, Cursor::new(data))
            .await
            .is_err()
    );
    assert_eq!(disk_view(&root), files);
    assert_eq!(store.generation().await, generation);
    assert_eq!(
        store
            .bundle
            .lock()
            .await
            .current_snapshot
            .as_ref()
            .expect("retained snapshot")
            .data,
        previous_snapshot
    );
    drop(store);
    let reopened = DurableStateMachine::open_existing(&root)
        .expect("prior bundle plus untouched journal reopen");
    assert_eq!(reopened.generation().await, generation);
    assert_eq!(
        reopened.client_status("selected").await.as_deref(),
        Some(value.as_str())
    );
    drop(reopened);
    fs::remove_dir_all(root).expect("cleanup");
}

#[tokio::test]
async fn legacy_byte_array_read_is_pure_then_snapshot_promotes_to_compact_format() {
    let root = root("legacy-compact");
    let mut store = DurableStateMachine::create(&root).expect("create");
    apply_value(&mut store, "synthetic-ciphertext".repeat(128)).await;
    let state = store.get_state_machine().await;
    let data = serde_json::to_vec(&state).expect("legacy snapshot data");
    let meta = SnapshotMetaOf::<TypeConfig> {
        last_log_id: state.last_applied_log,
        last_membership: state.last_membership.clone(),
    };
    let legacy = PersistentStateBundle {
        format_version: 1,
        journal_format: 1,
        generation: store.generation().await,
        state,
        current_snapshot: Some(PersistentSnapshot {
            meta,
            data,
            encoding: SnapshotEncoding::LegacyBytes,
        }),
    };
    write_json(&root.join("state-bundle.bin"), STATE_BUNDLE_MAGIC, &legacy)
        .expect("actual legacy bundle");
    initialize_state_journal(&root.join("state-machine.journal")).expect("checkpoint journal");
    drop(store);
    let before = disk_view(&root);
    let mut reopened = DurableStateMachine::open_existing(&root).expect("read old Vec format");
    assert_eq!(
        disk_view(&root),
        before,
        "opening v1 must not silently migrate it"
    );
    assert_eq!(reopened.bundle.lock().await.format_version, 1);
    let snapshot = reopened
        .build_snapshot()
        .await
        .expect("write new compact checkpoint");
    let after = disk_view(&root);
    let payload = read_payload(&root.join("state-bundle.bin"), STATE_BUNDLE_MAGIC)
        .expect("checksum/frame valid");
    let wire: serde_json::Value = serde_json::from_slice(&payload).expect("wire JSON");
    assert_eq!(wire["format_version"], 2);
    assert!(wire["current_snapshot"]["data"].is_string());
    assert!(
        serde_json::from_value::<Vec<u8>>(wire["current_snapshot"]["data"].clone()).is_err(),
        "old snapshot Vec decoder must reject new bytes"
    );
    assert_eq!(
        disk_view(&root),
        after,
        "rejected legacy decoding cannot mutate files"
    );
    drop(reopened);
    let mut compact = DurableStateMachine::open_existing(&root).expect("reopen compact format");
    let current = RaftStateMachine::get_current_snapshot(&mut compact)
        .await
        .expect("snapshot")
        .expect("present");
    assert_eq!(
        current.snapshot.into_inner(),
        snapshot.snapshot.into_inner()
    );
    assert_eq!(
        compact.bundle.lock().await.format_version,
        COMPACT_STATE_BUNDLE_FORMAT
    );
    drop(compact);
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn snapshot_representation_is_bound_to_version_and_base64_is_canonical() {
    let state = MemStoreStateMachine::default();
    let data = serde_json::to_vec(&state).expect("state");
    let meta = SnapshotMetaOf::<TypeConfig> {
        last_log_id: state.last_applied_log,
        last_membership: state.last_membership.clone(),
    };
    let mut bundle = PersistentStateBundle {
        format_version: 2,
        journal_format: 1,
        generation: 1,
        state,
        current_snapshot: Some(PersistentSnapshot {
            meta,
            data,
            encoding: SnapshotEncoding::CompactBase64,
        }),
    };
    assert!(bundle.validate().is_ok());
    bundle.format_version = 1;
    assert!(bundle.validate().is_err());
    bundle.format_version = 2;
    bundle.current_snapshot.as_mut().expect("snapshot").encoding = SnapshotEncoding::LegacyBytes;
    assert!(bundle.validate().is_err());
    bundle.format_version = 1;
    assert!(bundle.validate().is_ok());
    bundle.current_snapshot.as_mut().expect("snapshot").encoding = SnapshotEncoding::CompactBase64;
    let mut wire = serde_json::to_value(&bundle.current_snapshot).expect("snapshot wire");
    for invalid_data in ["!", "Zg==", "Zh", "AA\n"] {
        wire["data"] = serde_json::Value::String(invalid_data.into());
        assert!(serde_json::from_value::<PersistentSnapshot>(wire.clone()).is_err());
    }
}

#[test]
fn artifact_budget_includes_checksum_and_header_and_never_opens_a_temp_file() {
    let root = root("exact-bound");
    fs::create_dir_all(&root).expect("directory");
    let path = root.join("bounded.bin");
    let value = "synthetic";
    let payload = serde_json::to_vec(value).expect("payload");
    let exact = payload.len() + ENVELOPE_OVERHEAD_BYTES;
    write_json_with_bound(&path, STATE_BUNDLE_MAGIC, &value, exact).expect("inclusive bound");
    assert_eq!(fs::metadata(&path).expect("metadata").len(), exact as u64);
    let before = disk_view(&root);
    assert!(write_json_with_bound(&path, STATE_BUNDLE_MAGIC, &value, exact - 1).is_err());
    assert_eq!(disk_view(&root), before);
    assert_eq!(
        read_json::<String>(&path, STATE_BUNDLE_MAGIC).expect("reopen"),
        value
    );
    fs::remove_dir_all(root).expect("cleanup");
}
