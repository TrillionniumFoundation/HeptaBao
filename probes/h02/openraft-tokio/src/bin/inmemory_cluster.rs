#[path = "inmemory_cluster/network.rs"]
pub mod network;

mod inmemory_cluster {
    pub mod cluster;
    pub use crate::network;
}

#[allow(dead_code, unused_imports)]
mod hostile_cluster {
    include!("openraft_fault_lab/cluster.rs");

    /// Execute the stale committed-snapshot injection without emitting the
    /// fault-lab JSONL phase record. The in-memory behavior binary binds the
    /// result into its named snapshot-conflict case, while the dedicated
    /// fault-lab binary retains the isolated child/process-fatal boundary.
    pub async fn execute_inmemory_hostile_snapshot(seed: u64) -> AnyResult<Value> {
        let mut cluster = FaultCluster::new()?;
        cluster.bootstrap_three_voters().await?;

        let stale_log_id = cluster
            .write_log_id(210_001, format!("inmemory-stale-base-{seed:016x}"))
            .await?;
        let mut latest_log_id = stale_log_id;
        for offset in 0..6_u64 {
            latest_log_id = cluster
                .write_log_id(
                    210_100 + offset,
                    format!("inmemory-latest-{offset}-{seed:016x}"),
                )
                .await?;
        }
        cluster.wait_all_applied(latest_log_id.index).await?;
        cluster.trigger_snapshot(1, latest_log_id.index).await?;

        let mut snapshot = cluster.nodes[&1]
            .raft
            .get_snapshot()
            .await?
            .ok_or("in-memory hostile probe found no leader snapshot")?;
        let original_snapshot_log_id = snapshot.meta.last_log_id;
        snapshot.meta.last_log_id = Some(stale_log_id);

        let leader_vote = cluster.nodes[&1].raft.metrics().borrow_watched().vote;
        let before_metrics = cluster.nodes[&2].raft.metrics().borrow_watched().clone();
        let before_state = cluster.nodes[&2].state_machine.get_state_machine().await;
        let before_membership = serde_json::to_vec(&before_state.last_membership)?;
        let before_client_status = before_state.client_status.clone();

        let install_result = timeout(
            Duration::from_secs(10),
            cluster.nodes[&2]
                .raft
                .install_full_snapshot(leader_vote, snapshot),
        )
        .await;

        // A successful API response may be an idempotent no-op. Observe every
        // guarded state surface after a bounded settle interval and classify
        // only the semantic effect.
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
        let state_machine_unchanged = before_state.last_applied_log == after_state.last_applied_log
            && before_membership == after_membership
            && before_client_status == after_state.client_status;
        let guarded_state_unchanged = metrics_unchanged && state_machine_unchanged;

        let (transport_outcome, transport_detail, timed_out) = match install_result {
            Ok(Ok(response)) => ("ACKNOWLEDGED", format!("{response:?}"), false),
            Ok(Err(error)) => ("REJECTED_WITH_ERROR", error.to_string(), false),
            Err(_) => (
                "TIMED_OUT",
                "install_full_snapshot exceeded the in-memory deadline".to_owned(),
                true,
            ),
        };
        let rejected = !timed_out && guarded_state_unchanged;
        let outcome = if timed_out {
            "TIMED_OUT"
        } else if rejected {
            "REJECTED"
        } else {
            "ACCEPTED"
        };

        let observation = json!({
            "phase_reached": true,
            "outcome": outcome,
            "transport_outcome": transport_outcome,
            "transport_detail": transport_detail,
            "guarded_state_unchanged": guarded_state_unchanged,
            "metrics_unchanged": metrics_unchanged,
            "state_machine_unchanged": state_machine_unchanged,
            "stale_snapshot_log_id": stale_log_id.to_string(),
            "original_snapshot_log_id": original_snapshot_log_id
                .as_ref()
                .map(ToString::to_string),
            "before": {
                "last_log_index": before_metrics.last_log_index,
                "local_committed": before_metrics
                    .local_committed
                    .as_ref()
                    .map(ToString::to_string),
                "cluster_committed": before_metrics
                    .cluster_committed
                    .as_ref()
                    .map(ToString::to_string),
                "last_applied": before_metrics
                    .last_applied
                    .as_ref()
                    .map(ToString::to_string),
                "snapshot": before_metrics.snapshot.as_ref().map(ToString::to_string),
                "purged": before_metrics.purged.as_ref().map(ToString::to_string),
                "state_machine_last_applied": before_state
                    .last_applied_log
                    .as_ref()
                    .map(ToString::to_string),
                "client_status": before_client_status,
            },
            "after": {
                "last_log_index": after_metrics.last_log_index,
                "local_committed": after_metrics
                    .local_committed
                    .as_ref()
                    .map(ToString::to_string),
                "cluster_committed": after_metrics
                    .cluster_committed
                    .as_ref()
                    .map(ToString::to_string),
                "last_applied": after_metrics
                    .last_applied
                    .as_ref()
                    .map(ToString::to_string),
                "snapshot": after_metrics.snapshot.as_ref().map(ToString::to_string),
                "purged": after_metrics.purged.as_ref().map(ToString::to_string),
                "state_machine_last_applied": after_state
                    .last_applied_log
                    .as_ref()
                    .map(ToString::to_string),
                "client_status": after_state.client_status,
            },
        });
        cluster.shutdown().await;
        Ok(observation)
    }
}

use serde_json::{Value, json};

const CANDIDATE_ID: &str = "HB-DEP-RAFT-OPENRAFT";
const VERSION: &str = "0.10.0-alpha.33";
const PROFILE_ID: &str = "HB-H02-BEHAVIOR-RAFT-OPENRAFT-INMEMORY-0_10_0_ALPHA_33";
const SNAPSHOT_CASE_ID: &str = "raft-committed-snapshot-conflict-rejected";

fn parse_seed() -> u64 {
    let args = std::env::args().collect::<Vec<_>>();
    let raw = args
        .windows(2)
        .find(|pair| pair[0] == "--seed")
        .map(|pair| pair[1].as_str())
        .unwrap_or("0x5eed20260828cafe");
    let trimmed = raw.strip_prefix("0x").unwrap_or(raw);
    u64::from_str_radix(trimmed, 16).unwrap_or_else(|_| panic!("invalid seed: {raw}"))
}

fn bind_hostile_snapshot_observation(
    cases: &mut [Value],
    observation: &Value,
) -> Result<(), String> {
    let case = cases
        .iter_mut()
        .find(|case| case.get("case_id").and_then(Value::as_str) == Some(SNAPSHOT_CASE_ID))
        .ok_or_else(|| format!("missing in-memory case {SNAPSHOT_CASE_ID}"))?;

    let transport_pass = case.get("status").and_then(Value::as_str) == Some("PASS");
    let hostile_pass = observation.get("phase_reached").and_then(Value::as_bool) == Some(true)
        && observation.get("outcome").and_then(Value::as_str) == Some("REJECTED")
        && observation
            .get("guarded_state_unchanged")
            .and_then(Value::as_bool)
            == Some(true);

    let detail = case
        .get_mut("detail")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("{SNAPSHOT_CASE_ID} detail is missing or malformed"))?;
    detail.insert(
        "hostile_snapshot_conflict_injection".to_owned(),
        json!(if hostile_pass {
            "EXECUTED_REJECTED"
        } else {
            "EXECUTED_NOT_REJECTED"
        }),
    );
    detail.insert(
        "hostile_snapshot_phase_reached".to_owned(),
        observation
            .get("phase_reached")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    detail.insert(
        "hostile_guarded_state_unchanged".to_owned(),
        observation
            .get("guarded_state_unchanged")
            .cloned()
            .unwrap_or(Value::Bool(false)),
    );
    detail.insert(
        "hostile_snapshot_observation".to_owned(),
        observation.clone(),
    );
    case["assertion_count"] = json!(8);
    case["status"] = json!(if transport_pass && hostile_pass {
        "PASS"
    } else {
        "FAIL"
    });
    Ok(())
}

fn print_harness_error(message: String) {
    println!(
        "{}",
        json!({
            "kind": "harness_error",
            "status": "BLOCKED",
            "error_class": "OPENRAFT_INMEMORY_CLUSTER_EXECUTION_FAILED",
            "message": message,
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        })
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let seed = parse_seed();
    println!(
        "{}",
        json!({
            "kind": "meta",
            "candidate_id": CANDIDATE_ID,
            "version": VERSION,
            "profile_id": PROFILE_ID,
            "domain": "RAFT",
            "seed": format!("0x{seed:016x}"),
            "execution_scope": "REAL_OPENRAFT_INMEMORY_CLUSTER_WITH_TEST_MEMSTORE",
            "durability_class": "TEST_ONLY_IN_MEMORY_NO_PRODUCTION_CLAIM",
            "qualification": false,
            "selection_effect": "NONE",
            "authority_effect": "NONE",
        })
    );

    let mut cases = match inmemory_cluster::cluster::execute(seed).await {
        Ok(cases) => cases,
        Err(error) => {
            print_harness_error(error.to_string());
            std::process::exit(1);
        }
    };
    let hostile_observation = match hostile_cluster::execute_inmemory_hostile_snapshot(seed).await {
        Ok(observation) => observation,
        Err(error) => {
            print_harness_error(error.to_string());
            std::process::exit(1);
        }
    };
    if let Err(error) = bind_hostile_snapshot_observation(&mut cases, &hostile_observation) {
        print_harness_error(error);
        std::process::exit(1);
    }

    for case in cases {
        println!("{case}");
    }
}

#[cfg(test)]
mod tests {
    use super::{SNAPSHOT_CASE_ID, bind_hostile_snapshot_observation};
    use serde_json::json;

    fn cases() -> Vec<serde_json::Value> {
        vec![json!({
            "kind": "case",
            "case_id": SNAPSHOT_CASE_ID,
            "status": "PASS",
            "assertion_count": 4,
            "detail": {
                "full_snapshot_rpc_seen": true,
                "committed_index_monotonic": true,
                "lagging_node_converged": true,
                "hostile_snapshot_conflict_injection": "NOT_EXECUTED_PROMOTION_BLOCKER"
            }
        })]
    }

    #[test]
    fn rejected_hostile_snapshot_is_bound_into_named_case() {
        let mut values = cases();
        let observation = json!({
            "phase_reached": true,
            "outcome": "REJECTED",
            "guarded_state_unchanged": true
        });
        assert!(bind_hostile_snapshot_observation(&mut values, &observation).is_ok());
        assert_eq!(values[0]["status"], "PASS");
        assert_eq!(
            values[0]["detail"]["hostile_snapshot_conflict_injection"],
            "EXECUTED_REJECTED"
        );
        assert_eq!(values[0]["assertion_count"], 8);
    }

    #[test]
    fn accepted_or_state_changing_snapshot_forces_case_failure() {
        for observation in [
            json!({
                "phase_reached": true,
                "outcome": "ACCEPTED",
                "guarded_state_unchanged": false
            }),
            json!({
                "phase_reached": false,
                "outcome": "REJECTED",
                "guarded_state_unchanged": true
            }),
        ] {
            let mut values = cases();
            assert!(bind_hostile_snapshot_observation(&mut values, &observation).is_ok());
            assert_eq!(values[0]["status"], "FAIL");
            assert_eq!(
                values[0]["detail"]["hostile_snapshot_conflict_injection"],
                "EXECUTED_NOT_REJECTED"
            );
        }
    }
}
