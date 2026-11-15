//! Actual disk/apply/checkpoint/install boundaries for VOLATILE classification.
//! These store facts never grant ReadIndex, root publication or HTTP authority.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct OwnedRoot(PathBuf);
impl OwnedRoot {
    fn new(label: &str) -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "hb-generated-checkpoint-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn log(index: u64) -> LogIdOf<TypeConfig> {
    openraft::LogId {
        leader_id: openraft::impls::leader_id_adv::LeaderId {
            term: 7,
            node_id: 2,
        },
        index,
    }
}
async fn apply_blank(store: &mut DurableStateMachine, index: u64) -> io::Result<()> {
    let entry = EntryOf::<TypeConfig> {
        log_id: log(index),
        payload: EntryPayload::Blank,
    };
    let rows: Vec<io::Result<EntryResponder<TypeConfig>>> = vec![Ok((entry, None))];
    store.apply(futures::stream::iter(rows)).await
}

#[tokio::test]
async fn generated_checkpoint_chain_is_same_full_prefix_and_never_serialized() -> TestResult {
    let root = OwnedRoot::new("chain")?;
    let mut store = DurableStateMachine::create(root.0.join("state"))?;
    apply_blank(&mut store, 1).await?;
    let selected = store.generation().await;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    store.build_snapshot().await?;
    let first = store.generation().await;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        Some(first)
    );
    store.build_snapshot().await?;
    let second = store.generation().await;
    assert!(second > first);
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        Some(second)
    );
    assert_eq!(
        store
            .generated_checkpoint_transition_since(first, log(1))
            .await,
        Some(second)
    );
    assert_eq!(
        store
            .generated_checkpoint_transition_since(second, log(1))
            .await,
        None
    );
    let mut wrong_term = log(1);
    wrong_term.leader_id.term += 1;
    let mut wrong_node = log(1);
    wrong_node.leader_id.node_id += 1;
    for wrong in [wrong_term, wrong_node, log(2)] {
        assert_eq!(
            store
                .generated_checkpoint_transition_since(selected, wrong)
                .await,
            None
        );
    }
    let bytes = fs::read(store.snapshot_path())?;
    let payload = decode_envelope(STATE_BUNDLE_MAGIC, &bytes)?;
    let mut encoded: serde_json::Value = serde_json::from_slice(&payload)?;
    assert!(encoded.get("local_generated_checkpoint_start").is_none());
    // Even malicious serialized numeric metadata cannot populate the marker.
    encoded["local_generated_checkpoint_start"] = serde_json::json!(selected);
    let decoded: PersistentStateBundle = serde_json::from_value(encoded)?;
    assert!(decoded.local_generated_checkpoint_start.is_none());
    let reopened = DurableStateMachine::open_existing(root.0.join("state"))?;
    assert_eq!(reopened.generation().await, second);
    assert!(!reopened.same_instance(&store));
    assert_eq!(
        reopened
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    Ok(())
}

#[tokio::test]
async fn generated_checkpoint_apply_breaks_continuity_before_new_snapshot() -> TestResult {
    let root = OwnedRoot::new("apply-break")?;
    let mut store = DurableStateMachine::create(root.0.join("state"))?;
    apply_blank(&mut store, 1).await?;
    let selected = store.generation().await;
    store.build_snapshot().await?;
    assert!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await
            .is_some()
    );
    apply_blank(&mut store, 2).await?;
    let after_apply = store.generation().await;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    store.build_snapshot().await?;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(2))
            .await,
        None
    );
    assert!(
        store
            .generated_checkpoint_transition_since(after_apply, log(2))
            .await
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn generated_checkpoint_same_prefix_install_cannot_launder_local_history() -> TestResult {
    let root = OwnedRoot::new("install-break")?;
    let mut store = DurableStateMachine::create(root.0.join("state"))?;
    apply_blank(&mut store, 1).await?;
    let selected = store.generation().await;
    let snapshot = store.build_snapshot().await?;
    assert!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await
            .is_some()
    );
    // It is deliberately the identical full prefix and payload. Receiving or
    // installing it is still NOT a local generated-checkpoint continuation.
    store
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await?;
    let installed = store.generation().await;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    store.build_snapshot().await?;
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    assert!(
        store
            .generated_checkpoint_transition_since(installed, log(1))
            .await
            .is_some()
    );
    Ok(())
}

#[tokio::test]
async fn generated_checkpoint_failed_disk_preflight_does_not_create_transition() -> TestResult {
    let root = OwnedRoot::new("failed-checkpoint")?;
    let mut store = DurableStateMachine::create(root.0.join("state"))?;
    apply_blank(&mut store, 1).await?;
    let selected = store.generation().await;
    let before = fs::read(store.snapshot_path())?;
    store.artifact_bound = 1;
    assert!(store.build_snapshot().await.is_err());
    assert_eq!(store.generation().await, selected);
    assert_eq!(fs::read(store.snapshot_path())?, before);
    assert_eq!(
        store
            .generated_checkpoint_transition_since(selected, log(1))
            .await,
        None
    );
    Ok(())
}
