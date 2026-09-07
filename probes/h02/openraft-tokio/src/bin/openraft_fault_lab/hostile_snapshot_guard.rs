/// Execute the stale-snapshot injection and distinguish protocol acknowledgement
/// from an actual state regression. This file is included in the same module as
/// `cluster.rs`, so it can inspect the private test-cluster state without
/// widening the probe's public API.
pub async fn execute_hostile_snapshot_child_guarded(seed: u64) -> AnyResult<Value> {
    let mut cluster = FaultCluster::new()?;
    cluster.bootstrap_three_voters().await?;

    let stale_log_id = cluster
        .write_log_id(200_001, format!("stale-base-{seed:016x}"))
        .await?;
    let mut latest_log_id = stale_log_id;
    for offset in 0..6_u64 {
        latest_log_id = cluster
            .write_log_id(200_100 + offset, format!("latest-{offset}-{seed:016x}"))
            .await?;
    }
    cluster.wait_all_applied(latest_log_id.index).await?;
    cluster.trigger_snapshot(1, latest_log_id.index).await?;

    let mut snapshot = cluster.nodes[&1]
        .raft
        .get_snapshot()
        .await?
        .ok_or("leader returned no snapshot after snapshot trigger")?;
    let original_snapshot_log_id = snapshot.meta.last_log_id;
    snapshot.meta.last_log_id = Some(stale_log_id);

    let leader_vote = cluster.nodes[&1].raft.metrics().borrow_watched().vote;
    let before_metrics = cluster.nodes[&2].raft.metrics().borrow_watched().clone();
    let before_state = cluster.nodes[&2].state_machine.get_state_machine().await;
    let before_membership = serde_json::to_vec(&before_state.last_membership)?;
    let before_client_status = before_state.client_status.clone();

    println!(
        "{}",
        json!({
            "kind": "phase",
            "phase": HOSTILE_PHASE,
            "seed": format!("0x{seed:016x}"),
            "target_node": 2,
            "stale_snapshot_log_id": format!("{stale_log_id}"),
            "original_snapshot_log_id": original_snapshot_log_id.as_ref().map(|value| value.to_string()),
            "target_committed": before_metrics.local_committed.as_ref().map(|value| value.to_string()),
            "target_last_applied": before_metrics.last_applied.as_ref().map(|value| value.to_string()),
            "target_snapshot": before_metrics.snapshot.as_ref().map(|value| value.to_string()),
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        })
    );
    io::stdout().flush()?;

    let install_result = timeout(
        Duration::from_secs(10),
        cluster.nodes[&2]
            .raft
            .install_full_snapshot(leader_vote, snapshot),
    )
    .await;

    let result = match install_result {
        Ok(Ok(response)) => {
            // Protocol success is not proof that an obsolete snapshot was
            // installed. OpenRaft may acknowledge it as an idempotent no-op.
            // Bind the result to every safety-relevant local surface after a
            // bounded settle interval.
            sleep(Duration::from_millis(100)).await;
            let after_metrics = cluster.nodes[&2].raft.metrics().borrow_watched().clone();
            let after_state = cluster.nodes[&2].state_machine.get_state_machine().await;
            let after_membership = serde_json::to_vec(&after_state.last_membership)?;

            let metrics_unchanged = before_metrics.last_log_index == after_metrics.last_log_index
                && before_metrics.local_committed == after_metrics.local_committed
                && before_metrics.cluster_committed == after_metrics.cluster_committed
                && before_metrics.last_applied == after_metrics.last_applied
                && before_metrics.snapshot == after_metrics.snapshot
                && before_metrics.purged == after_metrics.purged;
            let state_machine_unchanged =
                before_state.last_applied_log == after_state.last_applied_log
                    && before_membership == after_membership
                    && before_client_status == after_state.client_status;
            let guarded_state_unchanged = metrics_unchanged && state_machine_unchanged;

            json!({
                "kind": "hostile_snapshot_child_result",
                // Preserve the existing wire contract: a stale snapshot that
                // produces no guarded state change is semantically rejected;
                // any guarded state mutation is accepted and therefore unsafe.
                "outcome": if guarded_state_unchanged { "REJECTED" } else { "ACCEPTED" },
                "detail": {
                    "classification": if guarded_state_unchanged {
                        "IGNORED_STALE_NO_STATE_CHANGE"
                    } else {
                        "STALE_SNAPSHOT_STATE_REGRESSION"
                    },
                    "candidate_response": format!("{response:?}"),
                    "guarded_state_unchanged": guarded_state_unchanged,
                    "metrics_unchanged": metrics_unchanged,
                    "state_machine_unchanged": state_machine_unchanged,
                    "before": {
                        "last_log_index": before_metrics.last_log_index,
                        "local_committed": before_metrics.local_committed.as_ref().map(|value| value.to_string()),
                        "cluster_committed": before_metrics.cluster_committed.as_ref().map(|value| value.to_string()),
                        "last_applied": before_metrics.last_applied.as_ref().map(|value| value.to_string()),
                        "snapshot": before_metrics.snapshot.as_ref().map(|value| value.to_string()),
                        "purged": before_metrics.purged.as_ref().map(|value| value.to_string()),
                        "state_machine_last_applied": before_state.last_applied_log.as_ref().map(|value| value.to_string()),
                        "client_status": before_client_status,
                    },
                    "after": {
                        "last_log_index": after_metrics.last_log_index,
                        "local_committed": after_metrics.local_committed.as_ref().map(|value| value.to_string()),
                        "cluster_committed": after_metrics.cluster_committed.as_ref().map(|value| value.to_string()),
                        "last_applied": after_metrics.last_applied.as_ref().map(|value| value.to_string()),
                        "snapshot": after_metrics.snapshot.as_ref().map(|value| value.to_string()),
                        "purged": after_metrics.purged.as_ref().map(|value| value.to_string()),
                        "state_machine_last_applied": after_state.last_applied_log.as_ref().map(|value| value.to_string()),
                        "client_status": after_state.client_status,
                    },
                },
            })
        }
        Ok(Err(error)) => json!({
            "kind": "hostile_snapshot_child_result",
            "outcome": "REJECTED",
            "detail": error.to_string(),
        }),
        Err(_) => json!({
            "kind": "hostile_snapshot_child_result",
            "outcome": "TIMED_OUT_AFTER_INJECTION",
            "detail": "install_full_snapshot exceeded the child deadline",
        }),
    };
    cluster.shutdown().await;
    Ok(result)
}
