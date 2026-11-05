//! One actual log-owner observation; this grants no consensus or snapshot authority.
use super::*;

pub(crate) struct NativeV6LogSlot {
    pub(crate) entry: Option<EntryOf<TypeConfig>>,
    pub(crate) last_purged: Option<LogIdOf<TypeConfig>>,
}

impl NativeV6LogSlot {
    pub(crate) fn compacted_through(&self, expected: LogIdOf<TypeConfig>) -> bool {
        self.entry.is_none()
            && self.last_purged.is_some_and(|purged| {
                purged.index >= expected.index
                    && purged >= expected
                    && (purged.index != expected.index || purged == expected)
            })
    }
}

impl DurableLogStore {
    /// Observe the exact slot and durable purge frontier under ONE owner lock.
    /// Purge publishes this state only after its actual journal/checkpoint I/O.
    /// Public Raft metrics may lag this storage handoff and are not substituted.
    /// The caller must bound the lock wait, validate exact retained payload or
    /// persisted snapshot provenance, and finally recheck its original witness.
    pub(crate) async fn native_v6_log_slot(&self, index: u64) -> io::Result<NativeV6LogSlot> {
        let state = self.state.lock().await;
        let entry = state
            .log
            .get(&index)
            .map(|bytes| serde_json::from_str(bytes).map_err(|error| invalid(error.to_string())))
            .transpose()?;
        Ok(NativeV6LogSlot {
            entry,
            last_purged: state.last_purged_log_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn native_v6_log_slot_keeps_real_purge_identity_missing_and_cold_fences() -> io::Result<()>
    {
        let root = std::env::temp_dir().join(format!(
            "hb-native-slot-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut store = DurableLogStore::create(&root)?;
        let log = LogIdOf::<TypeConfig> {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 2,
                node_id: 1,
            },
            index: 7,
        };
        let entry = EntryOf::<TypeConfig> {
            log_id: log,
            payload: EntryPayload::Blank,
        };
        {
            let mut state = store.state.lock().await;
            state.log.insert(
                log.index,
                serde_json::to_string(&entry).map_err(io::Error::other)?,
            );
            store.persist(&state)?;
        }
        let missing = store.native_v6_log_slot(8).await?;
        assert!(missing.entry.is_none() && missing.last_purged.is_none());
        assert!(
            !missing.compacted_through(log),
            "a missing slot is not evidence of compaction"
        );
        let selected = store.native_v6_log_slot(7).await?;
        assert_eq!(selected.entry.as_ref().map(|entry| entry.log_id), Some(log));
        assert!(!selected.compacted_through(log));
        let observer = store.clone();
        // Actual durable purge, with no Raft metrics publisher involved. The
        // observer sees the authoritative storage transition, not a metric.
        RaftLogStorage::purge(&mut store, log).await?;
        let purged = observer.native_v6_log_slot(7).await?;
        assert!(purged.entry.is_none() && purged.compacted_through(log));
        assert!(
            selected.entry.is_some(),
            "an earlier observation cannot silently rebase"
        );
        let foreign = LogIdOf::<TypeConfig> {
            leader_id: openraft::impls::leader_id_adv::LeaderId {
                term: 1,
                node_id: 2,
            },
            index: 7,
        };
        assert!(
            !purged.compacted_through(foreign),
            "same index with a different full LogId is not the original slot"
        );
        assert!(!purged.compacted_through(LogIdOf::<TypeConfig> { index: 8, ..log }));
        drop(observer);
        drop(store);
        let cold = DurableLogStore::open_existing(&root)?;
        assert!(cold.native_v6_log_slot(7).await?.compacted_through(log));
        assert!(
            !cold
                .native_v6_log_slot(8)
                .await?
                .compacted_through(LogIdOf::<TypeConfig> { index: 8, ..log })
        );
        drop(cold);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn native_v6_log_slot_lock_wait_is_bounded_by_callers_original_timeout() -> io::Result<()>
    {
        let root = std::env::temp_dir().join(format!(
            "hb-native-slot-bound-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let store = DurableLogStore::create(&root)?;
        let held = store.state.lock().await;
        let until = tokio::time::Instant::now() + Duration::from_millis(10);
        assert!(
            tokio::time::timeout_at(until, store.native_v6_log_slot(1))
                .await
                .is_err()
        );
        drop(held);
        let slot = store.native_v6_log_slot(1).await?;
        assert!(slot.entry.is_none() && slot.last_purged.is_none());
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
